/**
 * Canonical capture bundle format.
 *
 * ```
 * capture/
 *   manifest.json        deterministic manifest with bundle digest
 *   exchanges.ndjson     one stable-JSON exchange per line, ordered by sequence
 *   bodies/<sha256>.bin  content-addressed body bytes
 *   validation.ndjson    optional structured violations
 * ```
 */

import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import { stableStringify } from './stableJson.js';
import {
  BUNDLE_SCHEMA_VERSION,
  EXCHANGE_SCHEMA_VERSION,
  type CapturedExchange,
  type CapturedBody,
  type CaptureManifest,
} from '../capture/types.js';

export { stableStringify } from './stableJson.js';
export {
  exchangesToHar,
  exchangesToTrafficJsonl,
  type HarLog,
  type HarEntry,
  type TrafficLine,
} from './derive.js';

export const INLINE_BODY_LIMIT = 8 * 1024;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export interface CaptureBundle {
  readonly root: string;
  readonly manifest: CaptureManifest;
  readonly exchanges: readonly CapturedExchange[];
  readBody(body: CapturedBody): Buffer;
}

export function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Digest over normalized exchange content. Timing provenance (startedAt,
 * durationMs) is excluded so semantically identical captures compare equal.
 */
export function bundleDigest(exchanges: readonly CapturedExchange[]): string {
  const hash = createHash('sha256');
  for (const exchange of exchanges) {
    hash.update(stableStringify(semanticView(exchange)));
    hash.update('\n');
  }
  return hash.digest('hex');
}

function semanticView(exchange: CapturedExchange): Record<string, unknown> {
  const view: Record<string, unknown> = { ...exchange };
  delete view.startedAt;
  delete view.durationMs;
  return view;
}

export interface WriteBundleOptions {
  manifest: Omit<CaptureManifest, 'schemaVersion' | 'exchangeCount' | 'bundleDigest'>;
  exchanges: readonly CapturedExchange[];
  bodies: ReadonlyMap<string, Buffer>;
  validation?: readonly unknown[];
}

/**
 * Write a deterministic bundle. The output directory is created with
 * owner-only permissions; blob files are content-addressed by sha256.
 */
export function writeBundle(outputDir: string, options: WriteBundleOptions): CaptureManifest {
  const root = path.resolve(outputDir);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const bodiesDir = path.join(root, 'bodies');
  fs.mkdirSync(bodiesDir, { recursive: true, mode: 0o700 });

  const exchanges = [...options.exchanges].sort((a, b) => a.sequence - b.sequence);

  const referenced = new Set<string>();
  for (const exchange of exchanges) {
    for (const body of [exchange.request.body, exchange.response.body]) {
      if (body.storage.kind === 'blob') {
        const expected = `bodies/${body.sha256}.bin`;
        if (body.storage.path !== expected) {
          throw new Error(
            `Body blob path ${body.storage.path} is not content-addressed (expected ${expected})`
          );
        }
        referenced.add(body.sha256);
      }
    }
  }

  for (const digest of [...referenced].sort()) {
    const bytes = options.bodies.get(digest);
    if (!bytes) {
      throw new Error(`Missing body bytes for referenced blob ${digest}`);
    }
    if (sha256Hex(bytes) !== digest) {
      throw new Error(`Body bytes do not match digest ${digest}`);
    }
    writeFileAtomic(path.join(bodiesDir, `${digest}.bin`), bytes);
  }

  const ndjson = exchanges.map((e) => stableStringify(e)).join('\n');
  writeFileAtomic(path.join(root, 'exchanges.ndjson'), Buffer.from(ndjson + (ndjson ? '\n' : '')));

  if (options.validation && options.validation.length > 0) {
    const lines = options.validation.map((v) => stableStringify(v)).join('\n');
    writeFileAtomic(path.join(root, 'validation.ndjson'), Buffer.from(lines + '\n'));
  }

  const manifest: CaptureManifest = {
    schemaVersion: BUNDLE_SCHEMA_VERSION,
    ...options.manifest,
    exchangeCount: exchanges.length,
    bundleDigest: bundleDigest(exchanges),
  };
  writeFileAtomic(path.join(root, 'manifest.json'), Buffer.from(stableStringify(manifest) + '\n'));
  return manifest;
}

function writeFileAtomic(filePath: string, data: Buffer): void {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

/**
 * Load and verify a bundle. Rejects path traversal, symlinked entries, digest
 * mismatches, and unknown schema versions. Untrusted bundles are safe to load.
 */
export function loadBundle(bundleDir: string): CaptureBundle {
  const root = fs.realpathSync(path.resolve(bundleDir));

  const manifestPath = safeJoin(root, 'manifest.json');
  const manifestRaw = readRegularFile(manifestPath);
  const manifest = JSON.parse(manifestRaw.toString('utf-8')) as CaptureManifest;
  if (manifest.schemaVersion !== BUNDLE_SCHEMA_VERSION) {
    throw new Error(`Unsupported bundle schemaVersion: ${String(manifest.schemaVersion)}`);
  }

  const exchangesRaw = readRegularFile(safeJoin(root, 'exchanges.ndjson')).toString('utf-8');
  const exchanges: CapturedExchange[] = [];
  for (const line of exchangesRaw.split('\n')) {
    if (line.trim().length === 0) {
      continue;
    }
    const exchange = JSON.parse(line) as CapturedExchange;
    if (exchange.schemaVersion !== EXCHANGE_SCHEMA_VERSION) {
      throw new Error(`Unsupported exchange schemaVersion: ${String(exchange.schemaVersion)}`);
    }
    exchanges.push(exchange);
  }
  exchanges.sort((a, b) => a.sequence - b.sequence);

  if (exchanges.length !== manifest.exchangeCount) {
    throw new Error(
      `Manifest exchangeCount ${manifest.exchangeCount} does not match ${exchanges.length} exchanges`
    );
  }
  const digest = bundleDigest(exchanges);
  if (digest !== manifest.bundleDigest) {
    throw new Error('Bundle digest mismatch: exchanges.ndjson does not match manifest');
  }

  const readBody = (body: CapturedBody): Buffer => {
    let bytes: Buffer;
    if (body.storage.kind === 'inline-base64') {
      bytes = Buffer.from(body.storage.value, 'base64');
    } else {
      if (!SHA256_HEX.test(body.sha256)) {
        throw new Error(`Invalid body digest: ${body.sha256}`);
      }
      const expected = `bodies/${body.sha256}.bin`;
      if (body.storage.path !== expected) {
        throw new Error(`Blob path ${body.storage.path} is not content-addressed`);
      }
      bytes = readRegularFile(safeJoin(root, 'bodies', `${body.sha256}.bin`));
    }
    if (bytes.length !== body.size) {
      throw new Error(`Body size mismatch for ${body.sha256}`);
    }
    if (sha256Hex(bytes) !== body.sha256) {
      throw new Error(`Body digest mismatch for ${body.sha256}`);
    }
    return bytes;
  };

  return { root, manifest, exchanges, readBody };
}

/** Join path segments under root, rejecting traversal and absolute segments. */
export function safeJoin(root: string, ...segments: string[]): string {
  for (const segment of segments) {
    if (path.isAbsolute(segment) || segment.split(/[\\/]/).some((p) => p === '..' || p === '')) {
      throw new Error(`Unsafe path segment: ${segment}`);
    }
  }
  const joined = path.join(root, ...segments);
  const relative = path.relative(root, joined);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Path escapes bundle root: ${segments.join('/')}`);
  }
  return joined;
}

function readRegularFile(filePath: string): Buffer {
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) {
    throw new Error(`Refusing to read symlink in bundle: ${filePath}`);
  }
  if (!stat.isFile()) {
    throw new Error(`Not a regular file: ${filePath}`);
  }
  return fs.readFileSync(filePath);
}

/** Build a CapturedBody, inlining small payloads and blobbing large ones. */
export function makeCapturedBody(
  bytes: Buffer,
  mediaType: string | null,
  contentEncoding: string | null,
  bodies: Map<string, Buffer>
): CapturedBody {
  const digest = sha256Hex(bytes);
  if (bytes.length <= INLINE_BODY_LIMIT) {
    return {
      sha256: digest,
      size: bytes.length,
      mediaType,
      contentEncoding,
      storage: { kind: 'inline-base64', value: bytes.toString('base64') },
    };
  }
  bodies.set(digest, bytes);
  return {
    sha256: digest,
    size: bytes.length,
    mediaType,
    contentEncoding,
    storage: { kind: 'blob', path: `bodies/${digest}.bin` },
  };
}

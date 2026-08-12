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
  BUNDLE_LIMITS,
  BundleValidationError,
  validateExchange,
  validateManifest,
  validateSequenceOrder,
} from './validate.js';
import {
  BUNDLE_SCHEMA_VERSION,
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
export { BundleValidationError, BUNDLE_LIMITS } from './validate.js';

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
  let root = path.resolve(outputDir);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  // Never write through a symlinked output root (symlink-overwrite hardening).
  root = fs.realpathSync(root);
  const bodiesDir = path.join(root, 'bodies');
  fs.mkdirSync(bodiesDir, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(bodiesDir).isSymbolicLink()) {
    throw new Error(`Refusing to write through symlinked bodies directory: ${bodiesDir}`);
  }

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
 * Load and verify a bundle. Every field is runtime-validated with bounded
 * sizes before allocation, sequences must be strictly increasing, digests
 * are verified, and all file reads are confined to the bundle root with
 * symlinks rejected at every path component. Untrusted bundles are safe to
 * load.
 */
export function loadBundle(bundleDir: string): CaptureBundle {
  const root = fs.realpathSync(path.resolve(bundleDir));

  const manifestRaw = readContainedFile(root, ['manifest.json'], BUNDLE_LIMITS.maxManifestBytes);
  let manifestParsed: unknown;
  try {
    manifestParsed = JSON.parse(manifestRaw.toString('utf-8'));
  } catch {
    throw new BundleValidationError('manifest.json', 'not valid JSON');
  }
  const manifest = validateManifest(manifestParsed);

  const exchangesRaw = readContainedFile(
    root,
    ['exchanges.ndjson'],
    BUNDLE_LIMITS.maxExchanges * BUNDLE_LIMITS.maxNdjsonLineBytes
  ).toString('utf-8');
  const exchanges: CapturedExchange[] = [];
  for (const line of exchangesRaw.split('\n')) {
    if (line.trim().length === 0) {
      continue;
    }
    if (Buffer.byteLength(line) > BUNDLE_LIMITS.maxNdjsonLineBytes) {
      throw new BundleValidationError(
        `exchange[${exchanges.length}]`,
        `NDJSON line exceeds ${BUNDLE_LIMITS.maxNdjsonLineBytes} bytes`
      );
    }
    if (exchanges.length >= BUNDLE_LIMITS.maxExchanges) {
      throw new BundleValidationError(
        'exchanges.ndjson',
        `more than ${BUNDLE_LIMITS.maxExchanges} exchanges`
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new BundleValidationError(`exchange[${exchanges.length}]`, 'not valid JSON');
    }
    exchanges.push(validateExchange(parsed, exchanges.length));
  }
  validateSequenceOrder(exchanges);

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
      bytes = readContainedFile(root, ['bodies', `${body.sha256}.bin`], body.size);
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

/**
 * Read a file strictly contained under `root` (which must already be a
 * realpath): every intermediate component is lstat-checked so a symlinked
 * directory (e.g. bodies/ -> /etc) cannot escape, the leaf must be a regular
 * non-symlink file, its realpath must remain under root, and its size must
 * not exceed `maxBytes` before any allocation happens.
 */
function readContainedFile(root: string, segments: string[], maxBytes: number): Buffer {
  const filePath = safeJoin(root, ...segments);

  // Reject symlinks at every path component between root and the leaf.
  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing symlinked bundle path component: ${current}`);
    }
  }

  const stat = fs.lstatSync(filePath);
  if (!stat.isFile()) {
    throw new Error(`Not a regular file: ${filePath}`);
  }
  if (stat.size > maxBytes) {
    throw new Error(`File exceeds permitted size (${stat.size} > ${maxBytes}): ${filePath}`);
  }

  // Defense in depth against TOCTOU swaps: the resolved path of what we
  // actually open must still live under the bundle root.
  const real = fs.realpathSync(filePath);
  if (real !== filePath && !real.startsWith(root + path.sep)) {
    throw new Error(`Bundle file escapes root after resolution: ${filePath}`);
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

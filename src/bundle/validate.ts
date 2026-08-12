/**
 * Runtime validation for untrusted bundle input. JSON.parse alone proves
 * nothing about shape; every manifest and exchange field is checked here
 * before the rest of the loader trusts it.
 */

import {
  BUNDLE_SCHEMA_VERSION,
  EXCHANGE_SCHEMA_VERSION,
  type BodyStorage,
  type CaptureFailure,
  type CaptureManifest,
  type CapturedBody,
  type CapturedExchange,
  type CapturedHeaders,
  type StreamState,
  type ValidationSummary,
} from '../capture/types.js';

/** Bounds applied before parsing/allocating untrusted input. */
export const BUNDLE_LIMITS = {
  maxManifestBytes: 1024 * 1024,
  maxNdjsonLineBytes: 64 * 1024 * 1024,
  maxExchanges: 100_000,
  maxDeclaredBodyBytes: 4 * 1024 * 1024 * 1024,
  maxHeaderEntries: 512,
  maxHeaderValueBytes: 64 * 1024,
  maxStringBytes: 64 * 1024,
} as const;

export class BundleValidationError extends Error {
  constructor(location: string, problem: string) {
    super(`Invalid bundle: ${location}: ${problem}`);
    this.name = 'BundleValidationError';
  }
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const CAPTURE_MODES = new Set(['observe', 'exact']);
const STREAM_KINDS = new Set(['buffered', 'sse', 'other-stream']);
const FAILURE_STAGES = new Set([
  'request-capture',
  'upstream-connect',
  'response-capture',
  'persistence',
]);

function fail(location: string, problem: string): never {
  throw new BundleValidationError(location, problem);
}

function asRecord(value: unknown, location: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(location, 'expected an object');
  }
  return value as Record<string, unknown>;
}

function asString(
  value: unknown,
  location: string,
  maxBytes = BUNDLE_LIMITS.maxStringBytes
): string {
  if (typeof value !== 'string') {
    fail(location, 'expected a string');
  }
  if (Buffer.byteLength(value) > maxBytes) {
    fail(location, `string exceeds ${maxBytes} bytes`);
  }
  return value;
}

function asBoundedInt(value: unknown, location: string, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) {
    fail(location, 'expected a finite integer');
  }
  if (value < 0 || value > max) {
    fail(location, `out of bounds (0..${max})`);
  }
  return value;
}

function asFiniteNonNegative(value: unknown, location: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail(location, 'expected a finite non-negative number');
  }
  return value;
}

function asIsoDate(value: unknown, location: string): string {
  const text = asString(value, location, 128);
  if (Number.isNaN(Date.parse(text))) {
    fail(location, 'expected an ISO-8601 timestamp');
  }
  return text;
}

function asStringArray(value: unknown, location: string, maxEntries: number): string[] {
  if (!Array.isArray(value)) {
    fail(location, 'expected an array');
  }
  if (value.length > maxEntries) {
    fail(location, `more than ${maxEntries} entries`);
  }
  return value.map((entry, i) => asString(entry, `${location}[${i}]`));
}

export function validateManifest(raw: unknown): CaptureManifest {
  const m = asRecord(raw, 'manifest');
  if (m.schemaVersion !== BUNDLE_SCHEMA_VERSION) {
    fail('manifest.schemaVersion', `unsupported value ${String(m.schemaVersion)}`);
  }
  const mode = asString(m.mode, 'manifest.mode', 64);
  if (!CAPTURE_MODES.has(mode)) {
    fail('manifest.mode', `unknown mode ${mode}`);
  }
  const bundleDigest = asString(m.bundleDigest, 'manifest.bundleDigest', 128);
  if (!SHA256_HEX.test(bundleDigest)) {
    fail('manifest.bundleDigest', 'not a sha256 hex digest');
  }
  const targetOrigin = asString(m.targetOrigin, 'manifest.targetOrigin', 2048);
  try {
    void new URL(targetOrigin);
  } catch {
    fail('manifest.targetOrigin', 'not a valid URL');
  }
  const redaction = asRecord(m.redaction, 'manifest.redaction');
  let metadata: Record<string, string> | undefined;
  if (m.metadata !== undefined) {
    const metadataRecord = asRecord(m.metadata, 'manifest.metadata');
    metadata = {};
    for (const [key, value] of Object.entries(metadataRecord)) {
      metadata[asString(key, 'manifest.metadata key', 1024)] = asString(
        value,
        `manifest.metadata.${key}`
      );
    }
  }
  return {
    schemaVersion: BUNDLE_SCHEMA_VERSION,
    arbiterVersion: asString(m.arbiterVersion, 'manifest.arbiterVersion', 128),
    mode: mode as CaptureManifest['mode'],
    targetOrigin,
    startedAt: asIsoDate(m.startedAt, 'manifest.startedAt'),
    completedAt: asIsoDate(m.completedAt, 'manifest.completedAt'),
    exchangeCount: asBoundedInt(
      m.exchangeCount,
      'manifest.exchangeCount',
      BUNDLE_LIMITS.maxExchanges
    ),
    bundleDigest,
    redaction: {
      redactHeaders: asStringArray(
        redaction.redactHeaders,
        'manifest.redaction.redactHeaders',
        1024
      ),
      allowQuery: asStringArray(redaction.allowQuery, 'manifest.redaction.allowQuery', 1024),
    },
    ...(metadata !== undefined ? { metadata } : {}),
  };
}

function validateHeaders(raw: unknown, location: string): CapturedHeaders {
  const h = asRecord(raw, location);
  const valuesRecord = asRecord(h.values, `${location}.values`);
  const values: Record<string, string[]> = {};
  let entries = 0;
  for (const [name, headerValues] of Object.entries(valuesRecord)) {
    if (name !== name.toLowerCase()) {
      fail(`${location}.values`, `header name not lowercased: ${name}`);
    }
    if (!Array.isArray(headerValues)) {
      fail(`${location}.values.${name}`, 'expected an array of values');
    }
    entries += headerValues.length;
    if (entries > BUNDLE_LIMITS.maxHeaderEntries) {
      fail(`${location}.values`, `more than ${BUNDLE_LIMITS.maxHeaderEntries} header values`);
    }
    values[name] = headerValues.map((value, i) =>
      asString(value, `${location}.values.${name}[${i}]`, BUNDLE_LIMITS.maxHeaderValueBytes)
    );
  }
  return {
    values,
    redacted: asStringArray(h.redacted, `${location}.redacted`, BUNDLE_LIMITS.maxHeaderEntries),
  };
}

function validateBody(raw: unknown, location: string): CapturedBody {
  const b = asRecord(raw, location);
  const sha256 = asString(b.sha256, `${location}.sha256`, 128);
  if (!SHA256_HEX.test(sha256)) {
    fail(`${location}.sha256`, 'not a sha256 hex digest');
  }
  const size = asBoundedInt(b.size, `${location}.size`, BUNDLE_LIMITS.maxDeclaredBodyBytes);
  const storageRecord = asRecord(b.storage, `${location}.storage`);
  let storage: BodyStorage;
  if (storageRecord.kind === 'inline-base64') {
    const value = asString(
      storageRecord.value,
      `${location}.storage.value`,
      // base64 expansion of the inline limit, with slack for padding
      64 * 1024 * 1024
    );
    if (!BASE64.test(value) || value.length % 4 !== 0) {
      fail(`${location}.storage.value`, 'malformed base64');
    }
    // Cheap pre-decode size check: base64 length must be consistent with the
    // declared body size, so a tampered size cannot force overallocation.
    const decodedUpperBound = Math.ceil((value.length / 4) * 3);
    if (decodedUpperBound < size || decodedUpperBound > size + 3) {
      fail(`${location}.storage.value`, 'base64 length inconsistent with declared size');
    }
    storage = { kind: 'inline-base64', value };
  } else if (storageRecord.kind === 'blob') {
    const blobPath = asString(storageRecord.path, `${location}.storage.path`, 512);
    if (blobPath !== `bodies/${sha256}.bin`) {
      fail(`${location}.storage.path`, 'not content-addressed');
    }
    storage = { kind: 'blob', path: blobPath };
  } else {
    fail(`${location}.storage.kind`, `unknown kind ${String(storageRecord.kind)}`);
  }
  return {
    sha256,
    size,
    mediaType: b.mediaType === null ? null : asString(b.mediaType, `${location}.mediaType`, 1024),
    contentEncoding:
      b.contentEncoding === null
        ? null
        : asString(b.contentEncoding, `${location}.contentEncoding`, 256),
    storage,
  };
}

function validateStream(raw: unknown, location: string): StreamState {
  const s = asRecord(raw, location);
  const kind = asString(s.kind, `${location}.kind`, 64);
  if (!STREAM_KINDS.has(kind)) {
    fail(`${location}.kind`, `unknown kind ${kind}`);
  }
  for (const flag of ['completed', 'clientAborted', 'upstreamAborted'] as const) {
    if (typeof s[flag] !== 'boolean') {
      fail(`${location}.${flag}`, 'expected a boolean');
    }
  }
  return {
    kind: kind as StreamState['kind'],
    completed: s.completed as boolean,
    clientAborted: s.clientAborted as boolean,
    upstreamAborted: s.upstreamAborted as boolean,
    terminalMarker:
      s.terminalMarker === null
        ? null
        : asString(s.terminalMarker, `${location}.terminalMarker`, 256),
    error: s.error === null ? null : asString(s.error, `${location}.error`, 4096),
  };
}

function validateFailure(raw: unknown, location: string): CaptureFailure | null {
  if (raw === null) {
    return null;
  }
  const f = asRecord(raw, location);
  const stage = asString(f.stage, `${location}.stage`, 64);
  if (!FAILURE_STAGES.has(stage)) {
    fail(`${location}.stage`, `unknown stage ${stage}`);
  }
  return {
    stage: stage as CaptureFailure['stage'],
    message: asString(f.message, `${location}.message`, 4096),
  };
}

function validateValidationSummary(raw: unknown, location: string): ValidationSummary | null {
  if (raw === null) {
    return null;
  }
  const v = asRecord(raw, location);
  if (typeof v.valid !== 'boolean') {
    fail(`${location}.valid`, 'expected a boolean');
  }
  return {
    valid: v.valid,
    violationCount: asBoundedInt(v.violationCount, `${location}.violationCount`, 1_000_000),
  };
}

export function validateExchange(raw: unknown, index: number): CapturedExchange {
  const location = `exchange[${index}]`;
  const e = asRecord(raw, location);
  if (e.schemaVersion !== EXCHANGE_SCHEMA_VERSION) {
    fail(`${location}.schemaVersion`, `unsupported value ${String(e.schemaVersion)}`);
  }
  const request = asRecord(e.request, `${location}.request`);
  const response = asRecord(e.response, `${location}.response`);
  return {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence: asBoundedInt(e.sequence, `${location}.sequence`, BUNDLE_LIMITS.maxExchanges),
    startedAt: asIsoDate(e.startedAt, `${location}.startedAt`),
    durationMs: asFiniteNonNegative(e.durationMs, `${location}.durationMs`),
    request: {
      method: asString(request.method, `${location}.request.method`, 64),
      path: asString(request.path, `${location}.request.path`),
      httpVersion: asString(request.httpVersion, `${location}.request.httpVersion`, 16),
      headers: validateHeaders(request.headers, `${location}.request.headers`),
      body: validateBody(request.body, `${location}.request.body`),
    },
    response: {
      status: asBoundedInt(response.status, `${location}.response.status`, 999),
      statusText: asString(response.statusText, `${location}.response.statusText`, 1024),
      httpVersion: asString(response.httpVersion, `${location}.response.httpVersion`, 16),
      headers: validateHeaders(response.headers, `${location}.response.headers`),
      body: validateBody(response.body, `${location}.response.body`),
      stream: validateStream(response.stream, `${location}.response.stream`),
    },
    failure: validateFailure(e.failure, `${location}.failure`),
    validation: validateValidationSummary(e.validation, `${location}.validation`),
  };
}

/** Reject duplicate or unordered sequences: the NDJSON order is canonical. */
export function validateSequenceOrder(exchanges: readonly CapturedExchange[]): void {
  let previous = -1;
  for (const [index, exchange] of exchanges.entries()) {
    if (exchange.sequence <= previous) {
      fail(
        `exchange[${index}].sequence`,
        `duplicate or out-of-order sequence ${exchange.sequence} (previous ${previous})`
      );
    }
    previous = exchange.sequence;
  }
}

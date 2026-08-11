import zlib from 'zlib';
import type { CapturedBody, CapturedExchange } from './types.js';

export interface SecretFinding {
  /** e.g. "exchange 3 request body", "manifest metadata key foo" */
  location: string;
  /** Pattern or reason; never contains the full secret. */
  kind: string;
}

export class SecretFindingError extends Error {
  constructor(public readonly findings: SecretFinding[]) {
    super(
      `Secret scan failed: ${findings.length} finding(s). First: ${findings[0].kind} at ${findings[0].location}`
    );
    this.name = 'SecretFindingError';
  }
}

export interface SecretScanOptions {
  /** Exact secret values to reject anywhere. Never persisted. */
  rejectSecrets: string[];
  /** Media types allowed to remain unscanned binary. */
  allowBinaryMediaTypes: string[];
}

interface SecretPattern {
  kind: string;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { kind: 'anthropic-api-key', regex: /\bsk-ant-[A-Za-z0-9_-]{10,}/ },
  { kind: 'openai-api-key', regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/ },
  { kind: 'openrouter-api-key', regex: /\bsk-or-[A-Za-z0-9_-]{10,}/ },
  { kind: 'github-token', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}/ },
  { kind: 'aws-access-key-id', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: 'slack-token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  {
    kind: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  { kind: 'pem-private-key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  {
    kind: 'authorization-value',
    regex: /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_.-]{16,}/,
  },
];

const TEXTUAL_MEDIA = /json|text|xml|yaml|x-www-form-urlencoded|event-stream|javascript/i;

/**
 * Scan captured exchanges, header values, paths, metadata, and textual bodies
 * for secrets. Findings identify location and kind but never include the
 * complete secret value.
 */
export function scanExchanges(
  exchanges: readonly CapturedExchange[],
  bodies: ReadonlyMap<string, Buffer>,
  metadata: Record<string, string> | undefined,
  options: SecretScanOptions
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const rejectValues = options.rejectSecrets.filter((s) => s.length >= 4);

  const scanText = (text: string, location: string): void => {
    for (const value of rejectValues) {
      if (text.includes(value)) {
        findings.push({ location, kind: 'caller-rejected-secret' });
      }
    }
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(text)) {
        findings.push({ location, kind: pattern.kind });
      }
    }
  };

  if (metadata) {
    for (const [key, value] of Object.entries(metadata)) {
      scanText(`${key}=${value}`, `manifest metadata key ${key}`);
    }
  }

  for (const exchange of exchanges) {
    const where = `exchange ${exchange.sequence}`;
    scanText(exchange.request.path, `${where} request path`);
    scanHeaderValues(exchange.request.headers.values, `${where} request headers`, scanText);
    scanHeaderValues(exchange.response.headers.values, `${where} response headers`, scanText);
    scanBody(exchange.request.body, bodies, `${where} request body`, scanText, options, findings);
    scanBody(exchange.response.body, bodies, `${where} response body`, scanText, options, findings);
  }

  return findings;
}

function scanHeaderValues(
  values: Record<string, string[]>,
  location: string,
  scanText: (text: string, location: string) => void
): void {
  for (const [name, headerValues] of Object.entries(values)) {
    for (const value of headerValues) {
      scanText(value, `${location} (${name})`);
    }
  }
}

function scanBody(
  body: CapturedBody,
  bodies: ReadonlyMap<string, Buffer>,
  location: string,
  scanText: (text: string, location: string) => void,
  options: SecretScanOptions,
  findings: SecretFinding[]
): void {
  if (body.size === 0) {
    return;
  }
  const rawBytes = readBodyBytes(body, bodies);
  if (rawBytes === null) {
    findings.push({ location, kind: 'body-bytes-unavailable' });
    return;
  }
  // Scan the decoded analysis view; the canonical bytes stay untouched.
  const bytes = decodeAnalysisView(rawBytes, body.contentEncoding);
  if (bytes === null) {
    findings.push({
      location,
      kind: `undecodable-body (content-encoding: ${body.contentEncoding ?? 'unknown'})`,
    });
    return;
  }
  const mediaType = body.mediaType ?? '';
  if (TEXTUAL_MEDIA.test(mediaType) || looksLikeUtf8Text(bytes)) {
    scanText(bytes.toString('utf-8'), location);
    return;
  }
  const allowed = options.allowBinaryMediaTypes.some((allowedType) =>
    mediaType.toLowerCase().startsWith(allowedType.toLowerCase())
  );
  if (!allowed) {
    findings.push({
      location,
      kind: `unscannable-binary-body (${mediaType || 'unknown media type'})`,
    });
  }
}

function decodeAnalysisView(bytes: Buffer, contentEncoding: string | null): Buffer | null {
  if (contentEncoding === null || contentEncoding === 'identity') {
    return bytes;
  }
  try {
    switch (contentEncoding.toLowerCase()) {
      case 'gzip':
      case 'x-gzip':
        return zlib.gunzipSync(bytes);
      case 'deflate':
        return zlib.inflateSync(bytes);
      case 'br':
        return zlib.brotliDecompressSync(bytes);
      case 'zstd':
        return typeof zlib.zstdDecompressSync === 'function'
          ? zlib.zstdDecompressSync(bytes)
          : null;
      default:
        return null;
    }
  } catch {
    return null;
  }
}

function readBodyBytes(body: CapturedBody, bodies: ReadonlyMap<string, Buffer>): Buffer | null {
  if (body.storage.kind === 'inline-base64') {
    return Buffer.from(body.storage.value, 'base64');
  }
  return bodies.get(body.sha256) ?? null;
}

function looksLikeUtf8Text(bytes: Buffer): boolean {
  const sample = bytes.subarray(0, 4096);
  for (const byte of sample) {
    if (byte === 0) {
      return false;
    }
  }
  return Buffer.compare(Buffer.from(sample.toString('utf-8'), 'utf-8'), sample) === 0;
}

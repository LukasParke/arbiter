import type { IncomingHttpHeaders } from 'http';
import type { CapturedHeaders } from './types.js';
import type { RedactionPolicy } from './redaction.js';

/** RFC 9110 hop-by-hop headers, never forwarded or replayed. */
export const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/** Normalize Node's IncomingHttpHeaders into lowercased name -> value[] form. */
export function normalizeHeaders(headers: IncomingHttpHeaders): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    const key = name.toLowerCase();
    out[key] = Array.isArray(value) ? [...value] : [String(value)];
  }
  return out;
}

/**
 * Build lowercased name -> value[] headers from Node's rawHeaders list,
 * preserving duplicate header values as separate array entries (Node's
 * `.headers` object joins duplicates with ", ").
 */
export function headersFromRaw(rawHeaders: readonly string[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i].toLowerCase();
    (out[name] ??= []).push(rawHeaders[i + 1]);
  }
  return out;
}

/**
 * Apply a redaction policy to normalized headers: matching header values are
 * removed entirely and the names recorded as evidence.
 */
export function captureHeaders(
  headers: Record<string, string[]>,
  policy: RedactionPolicy
): CapturedHeaders {
  const values: Record<string, string[]> = {};
  const redacted: string[] = [];
  for (const [name, headerValues] of Object.entries(headers)) {
    if (policy.shouldRedactHeader(name)) {
      redacted.push(name);
    } else {
      values[name] = headerValues;
    }
  }
  redacted.sort();
  return { values, redacted };
}

/**
 * Headers safe to forward upstream: hop-by-hop and framing headers are
 * stripped; Node recomputes framing itself.
 */
export function forwardableHeaders(
  headers: Record<string, string[]>,
  options: { stripHost?: boolean } = {}
): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [name, values] of Object.entries(headers)) {
    if (HOP_BY_HOP_HEADERS.has(name)) {
      continue;
    }
    if (name === 'content-length') {
      continue; // recomputed from the streamed body
    }
    if (options.stripHost && name === 'host') {
      continue;
    }
    out[name] = values;
  }
  return out;
}

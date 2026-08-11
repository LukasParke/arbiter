/**
 * Canonical capture model.
 *
 * Arbiter guarantees exact application HTTP body bytes after transport
 * decoding: request bytes received from the client, response bytes delivered
 * to the client, ordered SSE bytes and terminal state, method/path/query,
 * response status, and selected end-to-end headers. Transport framing
 * (TLS records, HTTP/2 frames, TCP segmentation, chunk boundaries) is out of
 * scope.
 */

export const EXCHANGE_SCHEMA_VERSION = 1;

export interface CapturedHeaders {
  /** Lowercased header names; duplicate values remain arrays. */
  values: Record<string, string[]>;
  /** Names of headers whose values were removed before persistence. */
  redacted: string[];
}

export type BodyStorage =
  | { kind: 'inline-base64'; value: string }
  | { kind: 'blob'; path: string };

export interface CapturedBody {
  sha256: string;
  size: number;
  mediaType: string | null;
  contentEncoding: string | null;
  storage: BodyStorage;
}

export interface StreamState {
  kind: 'buffered' | 'sse' | 'other-stream';
  completed: boolean;
  clientAborted: boolean;
  upstreamAborted: boolean;
  terminalMarker: string | null;
  error: string | null;
}

export interface CaptureFailure {
  stage: 'request-capture' | 'upstream-connect' | 'response-capture' | 'persistence';
  message: string;
}

export interface ValidationSummary {
  valid: boolean;
  violationCount: number;
}

export interface CapturedExchange {
  schemaVersion: typeof EXCHANGE_SCHEMA_VERSION;
  sequence: number;
  startedAt: string;
  durationMs: number;
  request: {
    method: string;
    /** Path plus query. Query values may be redacted per policy. */
    path: string;
    httpVersion: string;
    headers: CapturedHeaders;
    body: CapturedBody;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: CapturedHeaders;
    body: CapturedBody;
    stream: StreamState;
  };
  failure: CaptureFailure | null;
  validation: ValidationSummary | null;
}

export const BUNDLE_SCHEMA_VERSION = 1;

export interface RedactionPolicySummary {
  redactHeaders: string[];
  allowQuery: string[];
}

export interface CaptureManifest {
  schemaVersion: typeof BUNDLE_SCHEMA_VERSION;
  arbiterVersion: string;
  mode: 'observe' | 'exact';
  /** Target origin with any query/credentials removed. */
  targetOrigin: string;
  startedAt: string;
  completedAt: string;
  exchangeCount: number;
  /** Digest over normalized exchange content, excluding timing provenance. */
  bundleDigest: string;
  redaction: RedactionPolicySummary;
  metadata?: Record<string, string>;
}

export type CaptureMode = 'observe' | 'exact';

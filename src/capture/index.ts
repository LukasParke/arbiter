export {
  startCaptureSession,
  type CaptureSession,
  type CaptureSessionOptions,
  type ExportOptions,
  type ExportResult,
  type ExchangeBodies,
} from './session.js';
export {
  RedactionPolicy,
  defaultRedactionPolicy,
  redactedQueryNames,
  REDACTED_VALUE,
  type RedactionPolicyOptions,
} from './redaction.js';
export {
  scanExchanges,
  SecretFindingError,
  type SecretFinding,
  type SecretScanOptions,
} from './secretScan.js';
export { SseParser, parseSseBody, terminalMarkerFor, type SseEvent } from './sse.js';
export { BodySink, BodyLimitExceededError, type BodyLimitPolicy } from './bodySink.js';
export {
  normalizeHeaders,
  headersFromRaw,
  captureHeaders,
  forwardableHeaders,
  HOP_BY_HOP_HEADERS,
} from './headers.js';
export * from './types.js';

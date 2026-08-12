/**
 * Sanitize an untrusted capture bundle: reload with full verification,
 * re-apply redaction, run the secret scanner, and emit a new deterministic
 * bundle. Never edits in place.
 */

import path from 'path';
import fs from 'fs';
import { loadBundle, writeBundle, makeCapturedBody, type CaptureBundle } from './index.js';
import { captureHeaders, type RedactionPolicy } from '../capture/index.js';
import { defaultRedactionPolicy } from '../capture/redaction.js';
import {
  scanExchanges,
  SecretFindingError,
  type SecretScanOptions,
} from '../capture/secretScan.js';
import { ARBITER_VERSION } from '../version.js';
import type { CapturedExchange } from '../capture/types.js';

export interface SanitizeOptions {
  output: string;
  redaction?: RedactionPolicy;
  rejectSecrets?: string[];
  allowBinaryMediaTypes?: string[];
}

export interface SanitizeResult {
  bundle: CaptureBundle;
  redactedHeaderCount: number;
}

export function sanitizeBundle(inputDir: string, options: SanitizeOptions): SanitizeResult {
  const input = loadBundle(inputDir);
  const outputRoot = path.resolve(options.output);
  if (path.resolve(inputDir) === outputRoot) {
    throw new Error('Sanitize never edits in place; choose a different output directory');
  }
  if (fs.existsSync(outputRoot) && fs.readdirSync(outputRoot).length > 0) {
    throw new Error(`Sanitize output directory is not empty: ${outputRoot}`);
  }
  const redaction = options.redaction ?? defaultRedactionPolicy;

  const bodies = new Map<string, Buffer>();
  let redactedHeaderCount = 0;

  const exchanges: CapturedExchange[] = input.exchanges.map((exchange) => {
    const requestBytes = input.readBody(exchange.request.body);
    const responseBytes = input.readBody(exchange.response.body);

    const requestHeaders = captureHeaders(exchange.request.headers.values, redaction);
    const responseHeaders = captureHeaders(exchange.response.headers.values, redaction);
    requestHeaders.redacted = [
      ...new Set([...requestHeaders.redacted, ...exchange.request.headers.redacted]),
    ].sort();
    responseHeaders.redacted = [
      ...new Set([...responseHeaders.redacted, ...exchange.response.headers.redacted]),
    ].sort();
    redactedHeaderCount += requestHeaders.redacted.length + responseHeaders.redacted.length;

    return {
      ...exchange,
      request: {
        ...exchange.request,
        path: redaction.redactPath(exchange.request.path),
        headers: requestHeaders,
        body: makeCapturedBody(
          requestBytes,
          exchange.request.body.mediaType,
          exchange.request.body.contentEncoding,
          bodies
        ),
      },
      response: {
        ...exchange.response,
        headers: responseHeaders,
        body: makeCapturedBody(
          responseBytes,
          exchange.response.body.mediaType,
          exchange.response.body.contentEncoding,
          bodies
        ),
      },
    };
  });

  const scanOptions: SecretScanOptions = {
    rejectSecrets: options.rejectSecrets ?? [],
    allowBinaryMediaTypes: options.allowBinaryMediaTypes ?? [],
  };
  const findings = scanExchanges(exchanges, bodies, input.manifest.metadata, scanOptions);
  if (findings.length > 0) {
    throw new SecretFindingError(findings);
  }

  writeBundle(outputRoot, {
    manifest: {
      arbiterVersion: ARBITER_VERSION,
      mode: input.manifest.mode,
      targetOrigin: input.manifest.targetOrigin,
      startedAt: input.manifest.startedAt,
      completedAt: input.manifest.completedAt,
      redaction: redaction.summary(),
      ...(input.manifest.metadata ? { metadata: input.manifest.metadata } : {}),
    },
    exchanges,
    bodies,
  });

  return { bundle: loadBundle(outputRoot), redactedHeaderCount };
}

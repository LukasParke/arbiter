/**
 * Replay of canonical capture bundles.
 *
 * Modes:
 * - exact-request + status-only / exact-response-body / semantic-json-response /
 *   semantic-sse-response.
 *
 * Credentials are injected only through a provider; the stored capture is
 * never updated with secrets.
 */

import http from 'http';
import https from 'https';
import { once } from 'events';
import { sha256Hex, type CaptureBundle } from '../bundle/index.js';
import { HOP_BY_HOP_HEADERS } from '../capture/headers.js';
import type { CapturedExchange } from '../capture/types.js';
import {
  compareExactBytes,
  compareSemanticJson,
  compareSemanticSse,
  type ComparisonResult,
  type JsonNormalization,
  type SseNormalization,
} from './compare.js';

export {
  compareExactBytes,
  compareSemanticJson,
  compareSemanticSse,
  firstJsonDiff,
  type ComparisonResult,
  type JsonNormalization,
  type SseNormalization,
} from './compare.js';

export type ReplayComparisonMode =
  | 'status-only'
  | 'exact-response-body'
  | 'semantic-json-response'
  | 'semantic-sse-response';

/** Supplies credential headers for an exchange at replay time. */
export type CredentialProvider = (
  exchange: CapturedExchange
) => Promise<Record<string, string>> | Record<string, string>;

export interface ReplayOptions {
  target: URL | string;
  mode: ReplayComparisonMode;
  credentialProvider?: CredentialProvider;
  normalization?: SseNormalization & JsonNormalization;
  /** Delay between requests in ms. */
  delayMs?: number;
  /** Reject TLS errors. Default true. */
  rejectUnauthorized?: boolean;
  /** Per-exchange timeout in ms. Default 120000. */
  timeoutMs?: number;
}

export interface ReplayExchangeResult {
  sequence: number;
  method: string;
  path: string;
  transportSuccess: boolean;
  /** sha256 of the request body bytes actually sent. */
  requestDigestSent: string;
  originalStatus: number;
  replayedStatus: number | null;
  statusMatch: boolean;
  comparison: ComparisonResult | null;
  normalizationApplied: string[];
  error: string | null;
  durationMs: number;
}

export interface ReplayReport {
  mode: ReplayComparisonMode;
  target: string;
  results: ReplayExchangeResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
  };
}

const REPLAY_SKIPPED_REQUEST_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  'content-length',
  'host',
  'accept-encoding',
]);

export async function replayCapture(
  bundle: CaptureBundle,
  options: ReplayOptions
): Promise<ReplayReport> {
  const target = typeof options.target === 'string' ? new URL(options.target) : options.target;
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error(`Unsupported replay target protocol: ${target.protocol}`);
  }
  const validModes: ReplayComparisonMode[] = [
    'status-only',
    'exact-response-body',
    'semantic-json-response',
    'semantic-sse-response',
  ];
  if (!validModes.includes(options.mode)) {
    throw new Error(`Unsupported replay comparison mode: ${String(options.mode)}`);
  }

  const results: ReplayExchangeResult[] = [];
  for (const exchange of bundle.exchanges) {
    results.push(await replayExchange(bundle, exchange, target, options));
    if (options.delayMs && options.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, options.delayMs));
    }
  }

  const errors = results.filter((r) => r.error !== null).length;
  const failed = results.filter((r) => r.error === null && !passedResult(r)).length;
  return {
    mode: options.mode,
    target: target.origin,
    results,
    summary: {
      total: results.length,
      passed: results.length - failed - errors,
      failed,
      errors,
    },
  };
}

function passedResult(result: ReplayExchangeResult): boolean {
  if (!result.transportSuccess || !result.statusMatch) {
    return false;
  }
  return result.comparison === null || result.comparison.match;
}

async function replayExchange(
  bundle: CaptureBundle,
  exchange: CapturedExchange,
  target: URL,
  options: ReplayOptions
): Promise<ReplayExchangeResult> {
  const start = Date.now();
  const requestBytes = bundle.readBody(exchange.request.body);
  const requestDigestSent = sha256Hex(requestBytes);
  const normalizationApplied = describeNormalization(options);

  const base: Omit<
    ReplayExchangeResult,
    'transportSuccess' | 'replayedStatus' | 'statusMatch' | 'comparison' | 'error' | 'durationMs'
  > = {
    sequence: exchange.sequence,
    method: exchange.request.method,
    path: exchange.request.path,
    requestDigestSent,
    originalStatus: exchange.response.status,
    normalizationApplied,
  };

  try {
    const headers: Record<string, string | string[]> = {};
    for (const [name, values] of Object.entries(exchange.request.headers.values)) {
      if (REPLAY_SKIPPED_REQUEST_HEADERS.has(name)) {
        continue;
      }
      headers[name] = values.length === 1 ? values[0] : values;
    }
    if (options.credentialProvider) {
      const credentials = await options.credentialProvider(exchange);
      for (const [name, value] of Object.entries(credentials)) {
        headers[name.toLowerCase()] = value;
      }
    }
    headers['host'] = target.host;
    headers['accept-encoding'] = 'identity';
    if (requestBytes.length > 0) {
      headers['content-length'] = String(requestBytes.length);
    }

    const requestFn = target.protocol === 'https:' ? https.request : http.request;
    const req = requestFn({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method: exchange.request.method,
      path: exchange.request.path,
      headers,
      rejectUnauthorized: options.rejectUnauthorized ?? true,
      timeout: options.timeoutMs ?? 120_000,
    } as https.RequestOptions);

    req.on('timeout', () => req.destroy(new Error('Replay request timed out')));
    if (requestBytes.length > 0) {
      req.write(requestBytes);
    }
    req.end();

    const [res] = (await once(req, 'response')) as [http.IncomingMessage];
    const chunks: Buffer[] = [];
    res.on('data', (chunk: Buffer) => chunks.push(chunk));
    await new Promise<void>((resolve, reject) => {
      res.on('end', resolve);
      res.on('error', reject);
    });
    const responseBytes = Buffer.concat(chunks);
    const replayedStatus = res.statusCode ?? 0;
    const statusMatch = replayedStatus === exchange.response.status;

    let comparison: ComparisonResult | null = null;
    if (options.mode !== 'status-only') {
      if (options.mode === 'semantic-sse-response' && exchange.response.stream.kind !== 'sse') {
        // Applying SSE comparison to a non-SSE exchange must be a visible
        // failure, never a vacuous pass.
        comparison = {
          match: false,
          detail: `Recorded exchange is not SSE (stream kind: ${exchange.response.stream.kind}); semantic-sse-response does not apply`,
        };
      } else {
        const expected = bundle.readBody(exchange.response.body);
        comparison = runComparison(options.mode, expected, responseBytes, options);
      }
    }

    return {
      ...base,
      transportSuccess: true,
      replayedStatus,
      statusMatch,
      comparison,
      error: null,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      ...base,
      transportSuccess: false,
      replayedStatus: null,
      statusMatch: false,
      comparison: null,
      error: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - start,
    };
  }
}

function runComparison(
  mode: Exclude<ReplayComparisonMode, 'status-only'>,
  expected: Buffer,
  actual: Buffer,
  options: ReplayOptions
): ComparisonResult {
  switch (mode) {
    case 'exact-response-body':
      return compareExactBytes(expected, actual);
    case 'semantic-json-response':
      return compareSemanticJson(expected, actual, options.normalization);
    case 'semantic-sse-response':
      return compareSemanticSse(expected, actual, options.normalization);
  }
}

function describeNormalization(options: ReplayOptions): string[] {
  const applied: string[] = [];
  if (options.normalization?.ignorePointers?.length) {
    applied.push(`ignore-pointers:${options.normalization.ignorePointers.join(',')}`);
  }
  if (options.normalization?.eventFilter?.length) {
    applied.push(`event-filter:${options.normalization.eventFilter.join(',')}`);
  }
  return applied;
}

/** Build a credential provider from env-to-header mappings like `ENV:header:prefix`. */
export function credentialProviderFromEnvMappings(
  mappings: readonly string[],
  env: NodeJS.ProcessEnv = process.env
): CredentialProvider {
  const resolved: Array<{ header: string; value: string }> = [];
  for (const mapping of mappings) {
    const [envName, header, ...prefixParts] = mapping.split(':');
    if (!envName || !header) {
      throw new Error(`Invalid credential mapping: ${mapping} (expected ENV:header[:prefix])`);
    }
    const secret = env[envName];
    if (secret === undefined || secret.length === 0) {
      throw new Error(`Credential environment variable ${envName} is not set`);
    }
    const prefix = prefixParts.join(':');
    resolved.push({ header, value: prefix ? `${prefix} ${secret}` : secret });
  }
  return () => {
    const headers: Record<string, string> = {};
    for (const { header, value } of resolved) {
      headers[header] = value;
    }
    return headers;
  };
}

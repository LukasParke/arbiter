import http from 'http';
import https from 'https';
import { once } from 'events';
import { ARBITER_VERSION } from '../version.js';
import { makeCapturedBody, writeBundle, type CaptureBundle, loadBundle } from '../bundle/index.js';
import { BodySink, BodyLimitExceededError, type BodyLimitPolicy } from './bodySink.js';
import { captureHeaders, forwardableHeaders, headersFromRaw } from './headers.js';
import { RedactionPolicy, defaultRedactionPolicy } from './redaction.js';
import { scanExchanges, SecretFindingError, type SecretScanOptions } from './secretScan.js';
import { SseParser } from './sse.js';
import {
  EXCHANGE_SCHEMA_VERSION,
  type CaptureFailure,
  type CaptureManifest,
  type CaptureMode,
  type CapturedExchange,
  type StreamState,
} from './types.js';

export interface CaptureSessionOptions {
  target: URL | string;
  listen?: { hostname?: string; port?: number };
  redaction?: RedactionPolicy;
  mode?: CaptureMode;
  /** Max in-memory body bytes before spill/fail. Default 32 MiB. */
  maxBodyBytes?: number;
  /** What to do when a body crosses maxBodyBytes. Default 'spill'. */
  bodyLimitPolicy?: BodyLimitPolicy;
  /** Called after each exchange settles (for derived views). */
  onExchange?: (exchange: CapturedExchange, bodies: ExchangeBodies) => void;
  /** Reject TLS errors when talking upstream. Default true. */
  rejectUnauthorized?: boolean;
}

export interface ExchangeBodies {
  requestBody: Buffer;
  responseBody: Buffer;
}

export interface ExportOptions {
  output: string;
  metadata?: Record<string, string>;
  /** Exact-secret values to reject anywhere in the bundle. */
  rejectSecrets?: string[];
  /** Media types allowed to remain un-scanned binary in exact mode. */
  allowBinaryMediaTypes?: string[];
}

export interface ExportResult {
  manifest: CaptureManifest;
  bundle: CaptureBundle;
}

export interface CaptureSession {
  readonly url: URL;
  exchanges(): readonly CapturedExchange[];
  failures(): readonly CaptureFailure[];
  waitForIdle(): Promise<void>;
  export(options: ExportOptions): Promise<ExportResult>;
  close(): Promise<void>;
}

const DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024;

export async function startCaptureSession(options: CaptureSessionOptions): Promise<CaptureSession> {
  const target = typeof options.target === 'string' ? new URL(options.target) : options.target;
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error(`Unsupported target protocol: ${target.protocol}`);
  }
  const mode: CaptureMode = options.mode ?? 'observe';
  const redaction = options.redaction ?? defaultRedactionPolicy;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const bodyLimitPolicy = options.bodyLimitPolicy ?? 'spill';
  const startedAt = new Date().toISOString();

  const exchanges: CapturedExchange[] = [];
  const bodies = new Map<string, Buffer>();
  const failures: CaptureFailure[] = [];
  const inFlight = new Set<Promise<void>>();
  let sequence = 0;

  const requestFn = target.protocol === 'https:' ? https.request : http.request;

  const server = http.createServer((clientReq, clientRes) => {
    const settled = handleExchange(clientReq, clientRes).catch((err: unknown) => {
      recordFailure({
        stage: 'response-capture',
        message: err instanceof Error ? err.message : String(err),
      });
    });
    inFlight.add(settled);
    void settled.finally(() => inFlight.delete(settled));
  });

  function recordFailure(failure: CaptureFailure): void {
    failures.push(failure);
  }

  async function handleExchange(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse
  ): Promise<void> {
    const seq = sequence++;
    const exchangeStart = Date.now();
    const startedAtIso = new Date(exchangeStart).toISOString();
    const method = clientReq.method ?? 'GET';
    const rawPath = clientReq.url ?? '/';

    const requestSink = new BodySink(maxBodyBytes, bodyLimitPolicy);
    const responseSink = new BodySink(maxBodyBytes, bodyLimitPolicy);
    let failure: CaptureFailure | null = null;
    let clientAborted = false;

    const requestHeaders = headersFromRaw(clientReq.rawHeaders);
    const upstreamHeaders = forwardableHeaders(requestHeaders, { stripHost: true });
    if (mode === 'exact') {
      // Ask for undecoded bytes so canonical capture equals the application
      // body. Upstreams may still compress; that is recorded as-is.
      upstreamHeaders['accept-encoding'] = ['identity'];
    }

    const upstreamReq = requestFn({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method,
      path: rawPath,
      headers: flattenHeaders({ ...upstreamHeaders, host: [target.host] }),
      rejectUnauthorized: options.rejectUnauthorized ?? true,
    } as https.RequestOptions);

    clientReq.on('data', (chunk: Buffer) => {
      try {
        requestSink.write(chunk);
      } catch (err) {
        failure = {
          stage: 'request-capture',
          message: err instanceof BodyLimitExceededError ? err.message : String(err),
        };
        clientReq.destroy();
        upstreamReq.destroy();
        return;
      }
      const ok = upstreamReq.write(chunk);
      if (!ok) {
        clientReq.pause();
        upstreamReq.once('drain', () => clientReq.resume());
      }
    });
    clientReq.on('end', () => upstreamReq.end());
    clientReq.on('aborted', () => {
      clientAborted = true;
      upstreamReq.destroy();
    });
    clientReq.on('error', () => {
      clientAborted = true;
      upstreamReq.destroy();
    });

    let upstreamRes: http.IncomingMessage;
    try {
      [upstreamRes] = (await once(upstreamReq, 'response')) as [http.IncomingMessage];
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!clientAborted) {
        failure = failure ?? { stage: 'upstream-connect', message };
        if (!clientRes.headersSent) {
          clientRes.writeHead(502, { 'content-type': 'application/json' });
        }
        if (!clientRes.writableEnded) {
          clientRes.end(JSON.stringify({ error: 'Bad gateway', message }));
        }
      }
      const requestDone = requestSink.finish();
      const responseDone = responseSink.finish();
      finalizeExchange({
        seq,
        startedAtIso,
        exchangeStart,
        method,
        rawPath,
        clientReq,
        requestHeaders,
        requestDone,
        responseDone,
        status: 502,
        statusText: 'Bad Gateway',
        responseHttpVersion: '1.1',
        responseHeaders: {},
        stream: {
          kind: 'buffered',
          completed: false,
          clientAborted,
          upstreamAborted: true,
          terminalMarker: null,
          error: message,
        },
        failure: failure ?? { stage: 'upstream-connect', message },
      });
      return;
    }

    const responseHeaders = headersFromRaw(upstreamRes.rawHeaders);
    const mediaType = firstHeader(responseHeaders, 'content-type');
    const isSse = mediaType !== null && mediaType.toLowerCase().includes('text/event-stream');
    const sseParser = isSse ? new SseParser() : null;

    const clientHeaders = forwardableHeaders(responseHeaders);
    clientRes.writeHead(
      upstreamRes.statusCode ?? 200,
      upstreamRes.statusMessage ?? '',
      flattenHeaders(clientHeaders)
    );
    clientRes.flushHeaders();

    let upstreamAborted = false;
    let completed = false;
    let streamError: string | null = null;

    upstreamRes.on('data', (chunk: Buffer) => {
      try {
        responseSink.write(chunk);
        sseParser?.feed(chunk);
      } catch (err) {
        failure = failure ?? {
          stage: 'response-capture',
          message: err instanceof Error ? err.message : String(err),
        };
        upstreamRes.destroy();
        return;
      }
      if (!clientRes.writableEnded) {
        const ok = clientRes.write(chunk);
        if (!ok) {
          upstreamRes.pause();
          clientRes.once('drain', () => upstreamRes.resume());
        }
      }
    });

    clientRes.on('close', () => {
      if (!clientRes.writableEnded) {
        clientAborted = true;
        upstreamRes.destroy();
      }
    });

    await new Promise<void>((resolve) => {
      upstreamRes.on('end', () => {
        completed = true;
        resolve();
      });
      upstreamRes.on('error', (err) => {
        upstreamAborted = true;
        streamError = err.message;
        resolve();
      });
      upstreamRes.on('close', () => resolve());
    });

    sseParser?.end();
    if (!clientRes.writableEnded) {
      clientRes.end();
    }

    const requestDone = requestSink.finish();
    const responseDone = responseSink.finish();

    finalizeExchange({
      seq,
      startedAtIso,
      exchangeStart,
      method,
      rawPath,
      clientReq,
      requestHeaders,
      requestDone,
      responseDone,
      status: upstreamRes.statusCode ?? 0,
      statusText: upstreamRes.statusMessage ?? '',
      responseHttpVersion: upstreamRes.httpVersion,
      responseHeaders,
      stream: {
        kind: isSse ? 'sse' : 'buffered',
        completed: completed && !clientAborted,
        clientAborted,
        upstreamAborted,
        terminalMarker: sseParser?.terminalMarker ?? null,
        error: streamError,
      },
      failure,
    });
  }

  interface FinalizeArgs {
    seq: number;
    startedAtIso: string;
    exchangeStart: number;
    method: string;
    rawPath: string;
    clientReq: http.IncomingMessage;
    requestHeaders: Record<string, string[]>;
    requestDone: ReturnType<BodySink['finish']>;
    responseDone: ReturnType<BodySink['finish']>;
    status: number;
    statusText: string;
    responseHttpVersion: string;
    responseHeaders: Record<string, string[]>;
    stream: StreamState;
    failure: CaptureFailure | null;
  }

  function finalizeExchange(args: FinalizeArgs): void {
    try {
      const requestBytes = args.requestDone.read();
      const responseBytes = args.responseDone.read();
      args.requestDone.dispose();
      args.responseDone.dispose();

      const exchange: CapturedExchange = {
        schemaVersion: EXCHANGE_SCHEMA_VERSION,
        sequence: args.seq,
        startedAt: args.startedAtIso,
        durationMs: Date.now() - args.exchangeStart,
        request: {
          method: args.method,
          path: redaction.redactPath(args.rawPath),
          httpVersion: args.clientReq.httpVersion,
          headers: captureHeaders(args.requestHeaders, redaction),
          body: makeCapturedBody(
            requestBytes,
            firstHeader(args.requestHeaders, 'content-type'),
            firstHeader(args.requestHeaders, 'content-encoding'),
            bodies
          ),
        },
        response: {
          status: args.status,
          statusText: args.statusText,
          httpVersion: args.responseHttpVersion,
          headers: captureHeaders(args.responseHeaders, redaction),
          body: makeCapturedBody(
            responseBytes,
            firstHeader(args.responseHeaders, 'content-type'),
            firstHeader(args.responseHeaders, 'content-encoding'),
            bodies
          ),
          stream: args.stream,
        },
        failure: args.failure,
        validation: null,
      };
      exchanges.push(exchange);
      if (args.failure) {
        failures.push(args.failure);
      }
      if (options.onExchange) {
        try {
          options.onExchange(exchange, { requestBody: requestBytes, responseBody: responseBytes });
        } catch {
          /* observer errors never affect capture */
        }
      }
    } catch (err) {
      recordFailure({
        stage: 'persistence',
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const hostname = options.listen?.hostname ?? '127.0.0.1';
  const port = options.listen?.port ?? 0;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, hostname, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('Failed to determine capture listener address');
  }
  const url = new URL(`http://${formatHost(address.address)}:${address.port}`);

  async function waitForIdle(): Promise<void> {
    while (inFlight.size > 0) {
      await Promise.allSettled([...inFlight]);
    }
  }

  return {
    url,
    exchanges: (): readonly CapturedExchange[] => [...exchanges],
    failures: (): readonly CaptureFailure[] => [...failures],
    waitForIdle,
    export: async (exportOptions: ExportOptions): Promise<ExportResult> => {
      await waitForIdle();

      if (mode === 'exact' && failures.length > 0) {
        throw new Error(
          `Exact capture failed closed: ${failures.length} capture failure(s). First: ${failures[0].message}`
        );
      }

      if (mode === 'exact') {
        const scanOptions: SecretScanOptions = {
          rejectSecrets: exportOptions.rejectSecrets ?? [],
          allowBinaryMediaTypes: exportOptions.allowBinaryMediaTypes ?? [],
        };
        const findings = scanExchanges(exchanges, bodies, exportOptions.metadata, scanOptions);
        if (findings.length > 0) {
          throw new SecretFindingError(findings);
        }
      }

      const manifest = writeBundle(exportOptions.output, {
        manifest: {
          arbiterVersion: ARBITER_VERSION,
          mode,
          targetOrigin: target.origin,
          startedAt,
          completedAt: new Date().toISOString(),
          redaction: redaction.summary(),
          ...(exportOptions.metadata ? { metadata: exportOptions.metadata } : {}),
        },
        exchanges,
        bodies,
      });
      return { manifest, bundle: loadBundle(exportOptions.output) };
    },
    close: async (): Promise<void> => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await waitForIdle();
    },
  };
}

function firstHeader(headers: Record<string, string[]>, name: string): string | null {
  const values = headers[name];
  return values && values.length > 0 ? values[0] : null;
}

function flattenHeaders(headers: Record<string, string[]>): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {};
  for (const [name, values] of Object.entries(headers)) {
    out[name] = values.length === 1 ? values[0] : values;
  }
  return out;
}

function formatHost(address: string): string {
  return address.includes(':') ? `[${address}]` : address;
}

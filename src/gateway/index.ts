/**
 * Credential-injecting gateway mode.
 *
 * An untrusted client authenticates with an opaque short-lived gateway token.
 * Arbiter validates the request against a policy, records it with the token
 * redacted, obtains the real upstream credential through an injected
 * provider, and attaches it only to the upstream request. The client process
 * and the capture artifact never see the real credential.
 */

import { spawn } from 'child_process';
import { createHash, timingSafeEqual } from 'crypto';
import http from 'http';
import https from 'https';
import { once } from 'events';
import { headersFromRaw, forwardableHeaders } from '../capture/headers.js';
import { startCaptureSession, type CaptureSession } from '../capture/session.js';
import { defaultRedactionPolicy, type RedactionPolicy } from '../capture/redaction.js';
import type { CaptureMode } from '../capture/types.js';

export interface GatewayPolicy {
  /** sha256 hex of the opaque gateway token. The token itself is never stored. */
  tokenSha256: string;
  /** ISO-8601 expiry for the token. */
  expiresAt: string;
  /** Allowed upstream origin, e.g. https://api.anthropic.com */
  targetOrigin: string;
  methods: string[];
  pathPrefixes: string[];
  /** When set, JSON request bodies must carry one of these `model` values. */
  models?: string[];
  maxRequests: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxDurationMs: number;
}

/** Returns the upstream credential header map. Output is treated as secret. */
export type GatewayCredentialProvider = () => Promise<Record<string, string>>;

export interface GatewayCaptureOptions {
  /** Capture semantics for gateway traffic. Default 'exact'. */
  mode?: CaptureMode;
  redaction?: RedactionPolicy;
  maxBodyBytes?: number;
}

export interface GatewayOptions {
  policy: GatewayPolicy;
  credentialProvider: GatewayCredentialProvider;
  listen?: { hostname?: string; port?: number };
  /**
   * Record allowed gateway traffic through an exact CaptureSession. The
   * session sits between the gateway and the upstream, so recorded exchanges
   * carry the client's byte-exact bodies with credential headers redacted;
   * neither the gateway token nor the upstream credential reaches the bundle.
   */
  capture?: GatewayCaptureOptions;
  /** Called for each decision; requests are observable, secrets are not. */
  onRequest?: (event: GatewayRequestEvent) => void;
  rejectUnauthorized?: boolean;
}

export interface GatewayRequestEvent {
  method: string;
  path: string;
  allowed: boolean;
  denyReason: string | null;
  status: number | null;
}

export interface GatewayServer {
  readonly url: URL;
  /** Requests served so far (allowed only). */
  readonly requestCount: number;
  /** The recording session when options.capture was set; otherwise null. */
  readonly capture: CaptureSession | null;
  close(): Promise<void>;
}

export class GatewayPolicyError extends Error {
  constructor(
    public readonly reason: string,
    public readonly statusCode: number
  ) {
    super(reason);
    this.name = 'GatewayPolicyError';
  }
}

export function validatePolicy(policy: GatewayPolicy): void {
  if (!/^[0-9a-f]{64}$/.test(policy.tokenSha256)) {
    throw new Error('policy.tokenSha256 must be a sha256 hex digest');
  }
  if (Number.isNaN(Date.parse(policy.expiresAt))) {
    throw new Error('policy.expiresAt must be an ISO-8601 timestamp');
  }
  const origin = new URL(policy.targetOrigin);
  if (origin.origin !== policy.targetOrigin) {
    throw new Error(`policy.targetOrigin must be an origin (got ${policy.targetOrigin})`);
  }
  if (policy.methods.length === 0 || policy.pathPrefixes.length === 0) {
    throw new Error('policy.methods and policy.pathPrefixes must be non-empty');
  }
  for (const field of [
    'maxRequests',
    'maxRequestBytes',
    'maxResponseBytes',
    'maxDurationMs',
  ] as const) {
    if (!Number.isFinite(policy[field]) || policy[field] <= 0) {
      throw new Error(`policy.${field} must be a positive number`);
    }
  }
}

export async function startGateway(options: GatewayOptions): Promise<GatewayServer> {
  validatePolicy(options.policy);
  const policy = options.policy;
  const startedAt = Date.now();
  let served = 0;

  // When capture is enabled the gateway routes upstream requests through an
  // exact CaptureSession pointed at the policy target. Recorded exchanges
  // carry the client's byte-exact bodies; the gateway token is stripped
  // before forwarding and the injected credential header is redacted by the
  // session's policy, so neither reaches the bundle.
  const captureSession: CaptureSession | null = options.capture
    ? await startCaptureSession({
        target: policy.targetOrigin,
        mode: options.capture.mode ?? 'exact',
        ...(options.capture.redaction ? { redaction: options.capture.redaction } : {}),
        ...(options.capture.maxBodyBytes !== undefined
          ? { maxBodyBytes: options.capture.maxBodyBytes }
          : {}),
        rejectUnauthorized: options.rejectUnauthorized ?? true,
      })
    : null;
  const upstreamUrl = captureSession ? captureSession.url : new URL(policy.targetOrigin);
  const captureRedaction = options.capture?.redaction ?? defaultRedactionPolicy;

  const emit = (event: GatewayRequestEvent): void => {
    try {
      options.onRequest?.(event);
    } catch {
      /* observer errors are not gateway errors */
    }
  };

  const deny = (
    res: http.ServerResponse,
    method: string,
    path: string,
    status: number,
    reason: string
  ): void => {
    emit({ method, path, allowed: false, denyReason: reason, status });
    if (!res.headersSent) {
      res.writeHead(status, { 'content-type': 'application/json' });
    }
    res.end(JSON.stringify({ error: 'gateway_denied', reason }));
  };

  const server = http.createServer((clientReq, clientRes) => {
    void handle(clientReq, clientRes).catch(() => {
      // Never expose internal error detail to the untrusted client.
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'content-type': 'application/json' });
      }
      if (!clientRes.writableEnded) {
        clientRes.end(JSON.stringify({ error: 'gateway_error' }));
      }
    });
  });

  async function handle(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse
  ): Promise<void> {
    const method = clientReq.method ?? 'GET';
    const path = clientReq.url ?? '/';

    // 1. Authenticate the opaque token.
    const auth = clientReq.headers.authorization ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : null;
    if (token === null || !tokenMatches(token, policy.tokenSha256)) {
      deny(clientRes, method, path, 401, 'invalid gateway token');
      clientReq.resume();
      return;
    }

    // 2. Policy checks.
    if (Date.now() > Date.parse(policy.expiresAt)) {
      deny(clientRes, method, path, 403, 'gateway token expired');
      clientReq.resume();
      return;
    }
    if (Date.now() - startedAt > policy.maxDurationMs) {
      deny(clientRes, method, path, 403, 'gateway session duration exceeded');
      clientReq.resume();
      return;
    }
    if (served >= policy.maxRequests) {
      deny(clientRes, method, path, 429, 'request count limit reached');
      clientReq.resume();
      return;
    }
    // Methods are compared case-sensitively against the normalized
    // uppercase form; a non-uppercase method is not a valid match.
    if (method !== method.toUpperCase() || !policy.methods.includes(method)) {
      deny(clientRes, method, path, 405, `method ${method} not allowed`);
      clientReq.resume();
      return;
    }
    if (!pathAllowed(path, policy.pathPrefixes)) {
      deny(clientRes, method, path, 403, 'path not allowed');
      clientReq.resume();
      return;
    }

    // 3. Buffer the request body under the byte ceiling (needed for the
    // model check, and gateway requests are bounded by policy anyway).
    // Crossing the ceiling yields a clean 413 response; the socket is not
    // destroyed before the response, and `connection: close` lets Node tear
    // the connection down after the response flushes.
    const body = await new Promise<Buffer | null>((resolve) => {
      const chunks: Buffer[] = [];
      let size = 0;
      clientReq.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > policy.maxRequestBytes) {
          clientReq.pause();
          resolve(null);
          return;
        }
        chunks.push(chunk);
      });
      clientReq.on('end', () => resolve(Buffer.concat(chunks)));
      clientReq.on('error', () => resolve(null));
    });
    if (body === null) {
      clientRes.setHeader('connection', 'close');
      deny(clientRes, method, path, 413, 'request byte limit exceeded');
      return;
    }

    if (policy.models && policy.models.length > 0) {
      const model = extractModel(body);
      if (model === null || !policy.models.includes(model)) {
        deny(clientRes, method, path, 403, `model ${model ?? '(none)'} not allowed`);
        return;
      }
    }

    // 4. Obtain the real credential and build the upstream request. The
    // client's gateway token never leaves this process.
    const requestHeaders = headersFromRaw(clientReq.rawHeaders);
    delete requestHeaders['authorization'];
    const upstreamHeaders = forwardableHeaders(requestHeaders, { stripHost: true });
    const flat: http.OutgoingHttpHeaders = {};
    for (const [name, values] of Object.entries(upstreamHeaders)) {
      flat[name] = values.length === 1 ? values[0] : values;
    }
    let credentialHeaders: Record<string, string> | null = null;
    try {
      credentialHeaders = await options.credentialProvider();
      if (captureSession) {
        // Fail closed: a credential header the capture policy would persist
        // must never be forwarded through the recording path.
        for (const name of Object.keys(credentialHeaders)) {
          if (!captureRedaction.shouldRedactHeader(name)) {
            throw new Error('credential header not covered by capture redaction policy');
          }
        }
      }
      for (const [name, value] of Object.entries(credentialHeaders)) {
        flat[name.toLowerCase()] = value;
      }
    } catch {
      // Provider failures must not leak detail to the untrusted client.
      deny(clientRes, method, path, 502, 'credential provider failed');
      return;
    } finally {
      credentialHeaders = null; // drop the reference immediately
    }
    flat['host'] = upstreamUrl.host;
    flat['content-length'] = String(body.length);

    const requestFn = upstreamUrl.protocol === 'https:' ? https.request : http.request;
    const upstreamReq = requestFn({
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || (upstreamUrl.protocol === 'https:' ? 443 : 80),
      method,
      path,
      headers: flat,
      rejectUnauthorized: options.rejectUnauthorized ?? true,
      // An upstream that accepts the connection but never responds must not
      // hold the client open forever; bound by the policy's session budget.
      timeout: policy.maxDurationMs,
    } as https.RequestOptions);
    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('upstream request timed out')));
    upstreamReq.on('error', () => {
      /* surfaced through the once(response) rejection or response handling */
    });
    if (body.length > 0) {
      upstreamReq.write(body);
    }
    upstreamReq.end();

    let upstreamRes: http.IncomingMessage;
    try {
      [upstreamRes] = (await once(upstreamReq, 'response')) as [http.IncomingMessage];
    } catch {
      // Upstream failure details are not exposed to the untrusted client.
      deny(clientRes, method, path, 502, 'upstream request failed');
      return;
    }

    served++;
    const responseHeaders = forwardableHeaders(headersFromRaw(upstreamRes.rawHeaders));
    const outHeaders: http.OutgoingHttpHeaders = {};
    for (const [name, values] of Object.entries(responseHeaders)) {
      outHeaders[name] = values.length === 1 ? values[0] : values;
    }
    clientRes.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.statusMessage ?? '', outHeaders);
    clientRes.flushHeaders();

    let responseBytes = 0;
    upstreamRes.on('data', (chunk: Buffer) => {
      responseBytes += chunk.length;
      if (responseBytes > policy.maxResponseBytes) {
        upstreamRes.destroy();
        clientRes.destroy();
        return;
      }
      if (!clientRes.writableEnded) {
        clientRes.write(chunk);
      }
    });
    await new Promise<void>((resolve) => {
      upstreamRes.on('end', resolve);
      upstreamRes.on('error', () => resolve());
      upstreamRes.on('close', resolve);
    });
    if (!clientRes.writableEnded && !clientRes.destroyed) {
      clientRes.end();
    }
    emit({ method, path, allowed: true, denyReason: null, status: upstreamRes.statusCode ?? null });
  }

  const hostname = options.listen?.hostname ?? '127.0.0.1';
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.listen?.port ?? 0, hostname, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('Failed to determine gateway listener address');
  }

  return {
    url: new URL(
      `http://${address.address.includes(':') ? `[${address.address}]` : address.address}:${address.port}`
    ),
    get requestCount(): number {
      return served;
    },
    capture: captureSession,
    close: async (): Promise<void> => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await captureSession?.close();
    },
  };
}

function tokenMatches(token: string, expectedSha256: string): boolean {
  const digest = createHash('sha256').update(token).digest();
  const expected = Buffer.from(expectedSha256, 'hex');
  return digest.length === expected.length && timingSafeEqual(digest, expected);
}

/**
 * Path allowlisting by path-segment semantics. Raw startsWith would let
 * `/v1secrets` match a `/v1` prefix and misses encoded traversal;
 * this decodes, normalizes, and rejects hostile shapes outright.
 */
export function pathAllowed(rawPath: string, prefixes: readonly string[]): boolean {
  const pathname = rawPath.split('?')[0];
  // Reject control characters, backslashes, and null bytes before decoding.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f\\]/.test(pathname)) {
    return false;
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return false; // malformed percent-encoding
  }
  // Re-check after decoding: %5C, %00, %2e%2e etc.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f\\]/.test(decoded)) {
    return false;
  }
  if (!decoded.startsWith('/')) {
    return false;
  }
  const segments = decoded.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    return false;
  }
  return prefixes.some((prefix) => {
    const normalized = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    if (normalized === '') {
      return true; // prefix "/" allows everything
    }
    return decoded === normalized || decoded.startsWith(normalized + '/');
  });
}

function extractModel(body: Buffer): string | null {
  try {
    const parsed = JSON.parse(body.toString('utf-8')) as { model?: unknown };
    return typeof parsed.model === 'string' ? parsed.model : null;
  } catch {
    return null;
  }
}

/**
 * Credential provider that runs a subprocess and consumes its stdout as the
 * secret value for the given header. stdout is never logged.
 */
export function credentialProviderFromCommand(
  command: string,
  header: string,
  options: { prefix?: string; timeoutMs?: number } = {}
): GatewayCredentialProvider {
  return async (): Promise<Record<string, string>> => {
    const secret = await new Promise<string>((resolve, reject) => {
      // detached: a timeout must kill the whole shell process tree.
      const child = spawn(command, {
        shell: true,
        stdio: ['ignore', 'pipe', 'inherit'],
        detached: process.platform !== 'win32',
      });
      const chunks: Buffer[] = [];
      const timer = setTimeout(() => {
        try {
          if (process.platform !== 'win32' && child.pid !== undefined) {
            process.kill(-child.pid, 'SIGKILL');
          } else {
            child.kill('SIGKILL');
          }
        } catch {
          /* already exited */
        }
        reject(new Error('Credential command timed out'));
      }, options.timeoutMs ?? 30_000);
      child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code !== 0) {
          reject(new Error(`Credential command exited with code ${String(code)}`));
          return;
        }
        resolve(Buffer.concat(chunks).toString('utf-8').trim());
      });
    });
    if (secret.length === 0) {
      throw new Error('Credential command produced no output');
    }
    return { [header]: options.prefix ? `${options.prefix} ${secret}` : secret };
  };
}

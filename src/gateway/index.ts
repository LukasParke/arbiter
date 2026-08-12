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

export interface GatewayOptions {
  policy: GatewayPolicy;
  credentialProvider: GatewayCredentialProvider;
  listen?: { hostname?: string; port?: number };
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
  const target = new URL(policy.targetOrigin);
  const startedAt = Date.now();
  let served = 0;

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
    void handle(clientReq, clientRes).catch((err: unknown) => {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'content-type': 'application/json' });
      }
      if (!clientRes.writableEnded) {
        clientRes.end(
          JSON.stringify({
            error: 'gateway_error',
            message: err instanceof Error ? err.message : 'unknown',
          })
        );
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
    if (!policy.methods.includes(method)) {
      deny(clientRes, method, path, 405, `method ${method} not allowed`);
      clientReq.resume();
      return;
    }
    const pathname = path.split('?')[0];
    if (!policy.pathPrefixes.some((prefix) => pathname.startsWith(prefix))) {
      deny(clientRes, method, path, 403, 'path not allowed');
      clientReq.resume();
      return;
    }

    // 3. Buffer the request body under the byte ceiling (needed for the
    // model check, and gateway requests are bounded by policy anyway).
    const chunks: Buffer[] = [];
    let size = 0;
    let overLimit = false;
    clientReq.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > policy.maxRequestBytes) {
        overLimit = true;
        clientReq.destroy();
        return;
      }
      chunks.push(chunk);
    });
    try {
      await once(clientReq, 'end');
    } catch {
      /* destroyed below-limit handling */
    }
    if (overLimit) {
      deny(clientRes, method, path, 413, 'request byte limit exceeded');
      return;
    }
    const body = Buffer.concat(chunks);

    if (policy.models && policy.models.length > 0) {
      const model = extractModel(body);
      if (model === null || !policy.models.includes(model)) {
        deny(clientRes, method, path, 403, `model ${model ?? '(none)'} not allowed`);
        return;
      }
    }

    // 4. Obtain the real credential and build the upstream request. The
    // client's gateway token never leaves this process.
    let credentialHeaders: Record<string, string> | null = await options.credentialProvider();

    const requestHeaders = headersFromRaw(clientReq.rawHeaders);
    delete requestHeaders['authorization'];
    const upstreamHeaders = forwardableHeaders(requestHeaders, { stripHost: true });
    const flat: http.OutgoingHttpHeaders = {};
    for (const [name, values] of Object.entries(upstreamHeaders)) {
      flat[name] = values.length === 1 ? values[0] : values;
    }
    for (const [name, value] of Object.entries(credentialHeaders)) {
      flat[name.toLowerCase()] = value;
    }
    flat['host'] = target.host;
    flat['content-length'] = String(body.length);
    credentialHeaders = null; // drop the reference immediately

    const requestFn = target.protocol === 'https:' ? https.request : http.request;
    const upstreamReq = requestFn({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method,
      path,
      headers: flat,
      rejectUnauthorized: options.rejectUnauthorized ?? true,
    } as https.RequestOptions);
    if (body.length > 0) {
      upstreamReq.write(body);
    }
    upstreamReq.end();

    let upstreamRes: http.IncomingMessage;
    try {
      [upstreamRes] = (await once(upstreamReq, 'response')) as [http.IncomingMessage];
    } catch (err) {
      deny(
        clientRes,
        method,
        path,
        502,
        `upstream error: ${err instanceof Error ? err.message : 'unknown'}`
      );
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
    close: (): Promise<void> => new Promise((resolve) => server.close(() => resolve())),
  };
}

function tokenMatches(token: string, expectedSha256: string): boolean {
  const digest = createHash('sha256').update(token).digest();
  const expected = Buffer.from(expectedSha256, 'hex');
  return digest.length === expected.length && timingSafeEqual(digest, expected);
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
      const child = spawn(command, { shell: true, stdio: ['ignore', 'pipe', 'inherit'] });
      const chunks: Buffer[] = [];
      const timer = setTimeout(() => {
        child.kill();
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

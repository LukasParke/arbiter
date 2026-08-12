import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import { once } from 'events';
import { createHash } from 'crypto';
import {
  startGateway,
  validatePolicy,
  credentialProviderFromCommand,
  type GatewayPolicy,
} from '../../src/gateway/index.js';

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()?.();
  }
});

const TOKEN = 'gw-test-token-abc';
const REAL_KEY = 'sk-real-upstream-credential';

function policyFor(origin: string, overrides: Partial<GatewayPolicy> = {}): GatewayPolicy {
  return {
    tokenSha256: createHash('sha256').update(TOKEN).digest('hex'),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    targetOrigin: origin,
    methods: ['POST'],
    pathPrefixes: ['/v1/'],
    maxRequests: 10,
    maxRequestBytes: 10_000,
    maxResponseBytes: 100_000,
    maxDurationMs: 60_000,
    ...overrides,
  };
}

async function startUpstream(): Promise<{
  origin: string;
  requests: Array<{ headers: http.IncomingHttpHeaders; body: Buffer; url: string }>;
}> {
  const requests: Array<{ headers: http.IncomingHttpHeaders; body: Buffer; url: string }> = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({ headers: req.headers, body: Buffer.concat(chunks), url: req.url ?? '' });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  cleanups.push(() => void server.close());
  const { port } = server.address() as { port: number };
  return { origin: `http://127.0.0.1:${port}`, requests };
}

async function startTestGateway(policy: GatewayPolicy, events: unknown[] = []) {
  const gateway = await startGateway({
    policy,
    credentialProvider: () => Promise.resolve({ 'x-api-key': REAL_KEY }),
    onRequest: (e) => events.push(e),
  });
  cleanups.push(() => gateway.close());
  return gateway;
}

describe('gateway policy enforcement', () => {
  it('rejects requests without a valid token', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin));

    const noAuth = await fetch(new URL('/v1/messages', gateway.url), {
      method: 'POST',
      body: '{}',
    });
    expect(noAuth.status).toBe(401);

    const badToken = await fetch(new URL('/v1/messages', gateway.url), {
      method: 'POST',
      headers: { authorization: 'Bearer wrong-token' },
      body: '{}',
    });
    expect(badToken.status).toBe(401);
    expect(upstream.requests).toHaveLength(0);
  });

  it('injects the real credential upstream without exposing it to the client', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin));

    const res = await fetch(new URL('/v1/messages', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: '{"model":"claude"}',
    });
    expect(res.status).toBe(200);

    // Upstream received the real key, not the gateway token.
    expect(upstream.requests[0].headers['x-api-key']).toBe(REAL_KEY);
    expect(JSON.stringify(upstream.requests[0].headers)).not.toContain(TOKEN);

    // Client response never contains the real key.
    const text = await res.text();
    expect(text).not.toContain(REAL_KEY);
    for (const [, value] of res.headers) {
      expect(value).not.toContain(REAL_KEY);
    }
  });

  it('enforces method and path restrictions', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin));
    const headers = { authorization: `Bearer ${TOKEN}` };

    expect(
      (await fetch(new URL('/v1/messages', gateway.url), { method: 'DELETE', headers })).status
    ).toBe(405);
    expect(
      (await fetch(new URL('/admin/keys', gateway.url), { method: 'POST', headers, body: '{}' }))
        .status
    ).toBe(403);
    expect(upstream.requests).toHaveLength(0);
  });

  it('enforces the request count limit', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin, { maxRequests: 2 }));
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };

    for (let i = 0; i < 2; i++) {
      const ok = await fetch(new URL('/v1/m', gateway.url), {
        method: 'POST',
        headers,
        body: '{}',
      });
      expect(ok.status).toBe(200);
    }
    const denied = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers,
      body: '{}',
    });
    expect(denied.status).toBe(429);
    expect(gateway.requestCount).toBe(2);
  });

  it('rejects expired tokens', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(
      policyFor(upstream.origin, { expiresAt: new Date(Date.now() - 1000).toISOString() })
    );
    const res = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: '{}',
    });
    expect(res.status).toBe(403);
  });

  it('rejects oversized requests with a clean 413 response', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin, { maxRequestBytes: 16 }));
    const res = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: 'x'.repeat(64),
    });
    // The contract: a readable 413 JSON response, never a destroyed socket.
    expect(res.status).toBe(413);
    const parsed = (await res.json()) as { error: string; reason: string };
    expect(parsed.error).toBe('gateway_denied');
    expect(parsed.reason).toMatch(/byte limit/);
    expect(upstream.requests).toHaveLength(0);

    // The gateway remains usable for subsequent (new-connection) requests.
    const ok = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: '{}',
    });
    expect(ok.status).toBe(200);
  });

  it('enforces model restrictions on JSON bodies', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(
      policyFor(upstream.origin, { models: ['allowed-model'] })
    );
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };

    const denied = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers,
      body: '{"model":"other-model"}',
    });
    expect(denied.status).toBe(403);

    const ok = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers,
      body: '{"model":"allowed-model"}',
    });
    expect(ok.status).toBe(200);
  });

  it('emits observable events without secrets', async () => {
    const upstream = await startUpstream();
    const events: unknown[] = [];
    const gateway = await startTestGateway(policyFor(upstream.origin), events);
    await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: '{}',
    });
    expect(events.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(REAL_KEY);
    expect(serialized).not.toContain(TOKEN);
  });
});

describe('gateway capture integration', () => {
  it('records client traffic through an exact capture session without the real credential', async () => {
    const upstream = await startUpstream();
    const events: unknown[] = [];
    const gateway = await startGateway({
      policy: policyFor(upstream.origin),
      credentialProvider: () => Promise.resolve({ 'x-api-key': REAL_KEY }),
      capture: {},
      onRequest: (e) => events.push(e),
    });
    cleanups.push(() => gateway.close());

    const body = '{ "model":  "claude" , "input": "hi"}';
    const res = await fetch(new URL('/v1/messages?trace=x', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body,
    });
    expect(res.status).toBe(200);
    await res.arrayBuffer();

    // Upstream still received the real key through the capture proxy.
    expect(upstream.requests[0].headers['x-api-key']).toBe(REAL_KEY);
    expect(upstream.requests[0].body.toString('utf-8')).toBe(body);

    // The capture session recorded the exchange byte-exactly.
    expect(gateway.capture).not.toBeNull();
    await gateway.capture!.waitForIdle();
    const exchanges = gateway.capture!.exchanges();
    expect(exchanges).toHaveLength(1);
    expect(exchanges[0].request.method).toBe('POST');
    expect(exchanges[0].request.path.split('?')[0]).toBe('/v1/messages');

    // Export the bundle and prove neither secret is anywhere in it.
    const os = await import('os');
    const fs = await import('fs');
    const path = await import('path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-gwcap-'));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const { bundle } = await gateway.capture!.export({ output: path.join(dir, 'capture') });

    expect(bundle.readBody(bundle.exchanges[0].request.body).toString('utf-8')).toBe(body);
    const everything =
      JSON.stringify(bundle.exchanges) +
      fs.readFileSync(path.join(dir, 'capture', 'exchanges.ndjson'), 'utf-8') +
      fs.readFileSync(path.join(dir, 'capture', 'manifest.json'), 'utf-8');
    expect(everything).not.toContain(REAL_KEY);
    expect(everything).not.toContain(TOKEN);
    expect(bundle.exchanges[0].request.headers.redacted).toContain('x-api-key');
  });

  it('fails closed when the credential header is not covered by capture redaction', async () => {
    const upstream = await startUpstream();
    const gateway = await startGateway({
      policy: policyFor(upstream.origin),
      // 'x-upstream-cred' does not match the default redaction policy, so
      // forwarding it through the recording path must be refused.
      credentialProvider: () => Promise.resolve({ 'x-upstream-cred': REAL_KEY }),
      capture: {},
    });
    cleanups.push(() => gateway.close());

    const res = await fetch(new URL('/v1/m', gateway.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(502);
    expect(upstream.requests).toHaveLength(0);

    // Nothing was recorded carrying the credential.
    await gateway.capture!.waitForIdle();
    expect(JSON.stringify(gateway.capture!.exchanges())).not.toContain(REAL_KEY);
  });
});

describe('validatePolicy', () => {
  it('rejects malformed policies', () => {
    const valid = policyFor('http://127.0.0.1:9999');
    expect(() => validatePolicy({ ...valid, tokenSha256: 'nope' })).toThrow(/sha256/);
    expect(() => validatePolicy({ ...valid, expiresAt: 'yesterday' })).toThrow(/ISO-8601/);
    expect(() => validatePolicy({ ...valid, targetOrigin: 'http://x.com/path' })).toThrow(/origin/);
    expect(() => validatePolicy({ ...valid, methods: [] })).toThrow(/non-empty/);
    expect(() => validatePolicy({ ...valid, maxRequests: 0 })).toThrow(/positive/);
  });
});

describe('credentialProviderFromCommand', () => {
  it('consumes subprocess stdout as the secret', async () => {
    const provider = credentialProviderFromCommand('echo "secret-from-command"', 'x-api-key');
    const headers = await provider();
    expect(headers['x-api-key']).toBe('secret-from-command');
  });

  it('applies a prefix', async () => {
    const provider = credentialProviderFromCommand('echo tok', 'authorization', {
      prefix: 'Bearer',
    });
    expect((await provider()).authorization).toBe('Bearer tok');
  });

  it('fails on non-zero exit', async () => {
    const provider = credentialProviderFromCommand('exit 3', 'x-api-key');
    await expect(provider()).rejects.toThrow(/code 3/);
  });

  it('fails on empty output', async () => {
    const provider = credentialProviderFromCommand('true', 'x-api-key');
    await expect(provider()).rejects.toThrow(/no output/);
  });
});

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

  it('enforces request byte ceilings', async () => {
    const upstream = await startUpstream();
    const gateway = await startTestGateway(policyFor(upstream.origin, { maxRequestBytes: 16 }));
    try {
      const res = await fetch(new URL('/v1/m', gateway.url), {
        method: 'POST',
        headers: { authorization: `Bearer ${TOKEN}` },
        body: 'x'.repeat(64),
      });
      expect([413, 0]).toContain(res.status);
    } catch {
      // socket destroyed mid-body is also acceptable fail-closed behavior
    }
    expect(upstream.requests).toHaveLength(0);
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

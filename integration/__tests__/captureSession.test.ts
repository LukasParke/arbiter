import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import { startCaptureSession, type CaptureSession } from '../../src/capture/index.js';
import { loadBundle, exchangesToHar, exchangesToTrafficJsonl } from '../../src/bundle/index.js';

interface Upstream {
  server: http.Server;
  url: string;
  requests: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders; body: Buffer }>;
}

async function startUpstream(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void
): Promise<Upstream> {
  const requests: Upstream['requests'] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body });
      handler(req, res, body);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as { port: number };
  return { server, url: `http://127.0.0.1:${address.port}`, requests };
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()?.();
  }
});

function tmpdir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-int-'));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function startSession(
  target: string,
  options: Partial<Parameters<typeof startCaptureSession>[0]> = {}
): Promise<CaptureSession> {
  const session = await startCaptureSession({ target, mode: 'exact', ...options });
  cleanups.push(() => session.close());
  return session;
}

describe('exact capture byte fidelity', () => {
  it('forwards request body bytes unchanged (whitespace and key order preserved)', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    const oddJson = '{  "zebra": 1,\n\t"alpha":   "two"  , "nested":{"b":1,"a":2}}';
    const res = await fetch(new URL('/v1/echo', session.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: oddJson,
    });
    expect(res.status).toBe(200);
    await res.arrayBuffer();
    await session.waitForIdle();

    expect(upstream.requests[0].body.toString('utf-8')).toBe(oddJson);
    const exchange = session.exchanges()[0];
    expect(exchange.request.body.size).toBe(Buffer.byteLength(oddJson));
    expect(exchange.failure).toBeNull();
  });

  it('forwards arbitrary binary request bytes unchanged', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    const binary = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 256));
    const res = await fetch(new URL('/upload', session.url), {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: binary,
    });
    await res.arrayBuffer();
    await session.waitForIdle();
    expect(upstream.requests[0].body.equals(binary)).toBe(true);
  });

  it('delivers and captures identical response bytes', async () => {
    const responseBytes = Buffer.from('{ "spaced" :  "json", "keys": ["z","a"] }');
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(responseBytes);
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    const res = await fetch(new URL('/v1/thing', session.url));
    const received = Buffer.from(await res.arrayBuffer());
    await session.waitForIdle();

    expect(received.equals(responseBytes)).toBe(true);
    const out = tmpdir();
    const { bundle } = await session.export({ output: path.join(out, 'capture') });
    const stored = bundle.readBody(bundle.exchanges[0].response.body);
    expect(stored.equals(responseBytes)).toBe(true);
  });

  it('streams SSE chunks to the client before upstream completion and records terminal state', async () => {
    let sendSecond: (() => void) | null = null;
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('event: message_start\ndata: {"type":"message_start"}\n\n');
      sendSecond = (): void => {
        res.write('event: message_stop\ndata: {"type":"message_stop"}\n\n');
        res.end();
      };
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    const res = await fetch(new URL('/v1/messages', session.url), { method: 'POST', body: '{}' });
    const reader = res.body!.getReader();

    const first = await reader.read();
    expect(Buffer.from(first.value!).toString('utf-8')).toContain('message_start');
    // Upstream has not finished yet — first chunk already delivered.
    sendSecond!();
    let rest = '';
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      rest += Buffer.from(chunk.value!).toString('utf-8');
    }
    expect(rest).toContain('message_stop');
    await session.waitForIdle();

    const exchange = session.exchanges()[0];
    expect(exchange.response.stream.kind).toBe('sse');
    expect(exchange.response.stream.completed).toBe(true);
    expect(exchange.response.stream.terminalMarker).toBe('message_stop');
  });

  it('records upstream abort with truncation evidence', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: {"partial":true}\n\n');
      setTimeout(() => res.destroy(), 20);
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url, { mode: 'observe' });
    const res = await fetch(new URL('/v1/stream', session.url));
    try {
      await res.arrayBuffer();
    } catch {
      // client may see the truncation as a fetch error
    }
    await session.waitForIdle();

    const exchange = session.exchanges()[0];
    expect(exchange.response.stream.completed).toBe(false);
    expect(exchange.response.stream.terminalMarker).toBeNull();
  });

  it('requests identity encoding in exact mode', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    await (await fetch(new URL('/x', session.url))).arrayBuffer();
    await session.waitForIdle();
    expect(upstream.requests[0].headers['accept-encoding']).toBe('identity');
  });

  it('records compressed bodies with their content encoding when upstream compresses anyway', async () => {
    const zlib = await import('zlib');
    const raw = Buffer.from('{"compressed":true}');
    const gz = zlib.gzipSync(raw);
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
      res.end(gz);
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    const res = await fetch(new URL('/z', session.url));
    // fetch transparently decompresses; verify the capture holds the wire bytes
    await res.arrayBuffer();
    await session.waitForIdle();

    const exchange = session.exchanges()[0];
    expect(exchange.response.body.contentEncoding).toBe('gzip');
    const out = tmpdir();
    const { bundle } = await session.export({ output: path.join(out, 'c') });
    expect(bundle.readBody(bundle.exchanges[0].response.body).equals(gz)).toBe(true);
  });

  it('captures duplicate headers as arrays', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.setHeader('x-multi', ['one', 'two']);
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    await (await fetch(new URL('/m', session.url))).arrayBuffer();
    await session.waitForIdle();
    expect(session.exchanges()[0].response.headers.values['x-multi']).toEqual(['one', 'two']);
  });

  it('redacts credential headers and query values in the capture but forwards them upstream', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    await (
      await fetch(new URL('/v1/data?api_key=leaky&page=1', session.url), {
        headers: { authorization: 'Bearer sk-test-secret-value' },
      })
    ).arrayBuffer();
    await session.waitForIdle();

    // Upstream still got the real credential
    expect(upstream.requests[0].headers.authorization).toBe('Bearer sk-test-secret-value');
    expect(upstream.requests[0].url).toContain('api_key=leaky');

    // Capture never holds it
    const exchange = session.exchanges()[0];
    expect(JSON.stringify(exchange)).not.toContain('sk-test-secret-value');
    expect(JSON.stringify(exchange)).not.toContain('leaky');
    expect(exchange.request.headers.redacted).toContain('authorization');
  });

  it('fails exact export when a body limit failure occurred', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url, {
      maxBodyBytes: 8,
      bodyLimitPolicy: 'fail',
    });
    try {
      await fetch(new URL('/big', session.url), {
        method: 'POST',
        body: 'this body exceeds eight bytes',
      });
    } catch {
      // proxy destroys the socket; fetch failure is expected
    }
    await session.waitForIdle();
    const out = tmpdir();
    await expect(session.export({ output: path.join(out, 'c') })).rejects.toThrow(/fail(ed)? closed/i);
  });

  it('spills large bodies without truncation under spill policy', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url, { maxBodyBytes: 16, bodyLimitPolicy: 'spill' });
    const payload = Buffer.alloc(1024, 0x61);
    await (
      await fetch(new URL('/big', session.url), { method: 'POST', body: payload })
    ).arrayBuffer();
    await session.waitForIdle();

    expect(upstream.requests[0].body.equals(payload)).toBe(true);
    expect(session.exchanges()[0].request.body.size).toBe(1024);
    const out = tmpdir();
    const { bundle } = await session.export({ output: path.join(out, 'c') });
    expect(bundle.readBody(bundle.exchanges[0].request.body).equals(payload)).toBe(true);
  });

  it('fails exact export when a rejected secret appears in traffic', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    await (
      await fetch(new URL('/v1/x', session.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"prompt":"my key is super-sekrit-value-123"}',
      })
    ).arrayBuffer();
    await session.waitForIdle();

    const out = tmpdir();
    await expect(
      session.export({ output: path.join(out, 'c'), rejectSecrets: ['super-sekrit-value-123'] })
    ).rejects.toThrow(/secret scan failed/i);
  });

  it('returns 502 and records failure when upstream is unreachable', async () => {
    const session = await startSession('http://127.0.0.1:1', { mode: 'observe' });
    const res = await fetch(new URL('/x', session.url));
    expect(res.status).toBe(502);
    await session.waitForIdle();
    const exchange = session.exchanges()[0];
    expect(exchange.failure?.stage).toBe('upstream-connect');
  });

  it('exports a loadable deterministic bundle with derived HAR and JSONL views', async () => {
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url);
    await (
      await fetch(new URL('/v1/messages', session.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"model":"m"}',
      })
    ).arrayBuffer();
    await session.waitForIdle();

    const out = tmpdir();
    const { bundle, manifest } = await session.export({ output: path.join(out, 'capture') });
    expect(manifest.exchangeCount).toBe(1);
    expect(manifest.mode).toBe('exact');

    const reloaded = loadBundle(path.join(out, 'capture'));
    expect(reloaded.manifest.bundleDigest).toBe(manifest.bundleDigest);

    const har = exchangesToHar(reloaded.exchanges, reloaded.manifest.targetOrigin, reloaded.readBody);
    expect(har.log.entries).toHaveLength(1);
    expect(har.log.entries[0].request.postData?.text).toBe('{"model":"m"}');
    expect(har.log.entries[0].response.content.text).toBe('{"ok":true}');

    const jsonl = exchangesToTrafficJsonl(reloaded.exchanges, reloaded.readBody);
    const line = JSON.parse(jsonl.trim());
    expect(line.method).toBe('POST');
    expect(line.response_status).toBe(200);
  });

  it('round-trips binary response bytes through HAR base64 encoding', async () => {
    const binary = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x80]);
    const upstream = await startUpstream((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(binary);
    });
    cleanups.push(() => void upstream.server.close());

    const session = await startSession(upstream.url, { mode: 'observe' });
    await (await fetch(new URL('/bin', session.url))).arrayBuffer();
    await session.waitForIdle();

    const out = tmpdir();
    const { bundle } = await session.export({ output: path.join(out, 'c') });
    const har = exchangesToHar(bundle.exchanges, bundle.manifest.targetOrigin, bundle.readBody);
    const content = har.log.entries[0].response.content;
    expect(content.encoding).toBe('base64');
    expect(Buffer.from(content.text, 'base64').equals(binary)).toBe(true);
  });
});

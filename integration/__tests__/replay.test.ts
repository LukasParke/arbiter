import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import { startCaptureSession } from '../../src/capture/index.js';
import { loadBundle, type CaptureBundle } from '../../src/bundle/index.js';
import { replayCapture, credentialProviderFromEnvMappings } from '../../src/replay/index.js';

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()?.();
  }
});

function tmpdir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-replay-'));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

async function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void
): Promise<{ url: string; requests: RecordedRequest[]; close: () => void }> {
  const requests: RecordedRequest[] = [];
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
  const { port } = server.address() as { port: number };
  const close = (): void => void server.close();
  cleanups.push(close);
  return { url: `http://127.0.0.1:${port}`, requests, close };
}

async function captureOne(
  upstreamUrl: string,
  makeRequest: (proxyUrl: URL) => Promise<void>
): Promise<CaptureBundle> {
  const session = await startCaptureSession({ target: upstreamUrl, mode: 'exact' });
  await makeRequest(session.url);
  await session.waitForIdle();
  const out = tmpdir();
  const { bundle } = await session.export({ output: path.join(out, 'capture') });
  await session.close();
  return bundle;
}

describe('replayCapture', () => {
  it('resends exact request body bytes and safe headers', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    const oddBody = '{  "keep":   "spacing", "z": 1 }';
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (
        await fetch(new URL('/v1/messages?page=x', proxyUrl), {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-request-tag': 'replay-me',
            authorization: 'Bearer sk-original-secret',
          },
          body: oddBody,
        })
      ).arrayBuffer();
    });

    const replayTarget = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    const report = await replayCapture(bundle, {
      target: replayTarget.url,
      mode: 'semantic-json-response',
    });

    expect(report.summary.passed).toBe(1);
    const sent = replayTarget.requests[0];
    expect(sent.body.toString('utf-8')).toBe(oddBody);
    expect(sent.method).toBe('POST');
    expect(sent.headers['x-request-tag']).toBe('replay-me');
    expect(sent.headers['content-type']).toBe('application/json');
    // Redacted credential is NOT replayed
    expect(sent.headers.authorization).toBeUndefined();
  });

  it('injects credentials through a provider without touching the bundle', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/v1/x', proxyUrl))).arrayBuffer();
    });

    const replayTarget = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    const report = await replayCapture(bundle, {
      target: replayTarget.url,
      mode: 'status-only',
      credentialProvider: () => ({ authorization: 'Bearer sk-injected' }),
    });
    expect(report.summary.passed).toBe(1);
    expect(replayTarget.requests[0].headers.authorization).toBe('Bearer sk-injected');
    // The stored bundle remains credential-free
    expect(
      JSON.stringify(bundle.exchanges.map((e) => e.request.headers))
    ).not.toContain('sk-injected');
  });

  it('supports env-mapping credential providers', async () => {
    process.env.ARBITER_TEST_KEY = 'test-value-123';
    cleanups.push(() => {
      delete process.env.ARBITER_TEST_KEY;
    });
    const provider = credentialProviderFromEnvMappings([
      'ARBITER_TEST_KEY:authorization:Bearer',
    ]);
    const headers = await provider(null as never);
    expect(headers.authorization).toBe('Bearer test-value-123');
  });

  it('rejects unset credential env vars', () => {
    expect(() => credentialProviderFromEnvMappings(['ARBITER_MISSING_VAR:authorization'])).toThrow(
      /not set/
    );
  });

  it('compares exact response bytes with first-diff offsets', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('response-abc');
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/t', proxyUrl))).arrayBuffer();
    });

    const differentTarget = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('response-abX');
    });
    const report = await replayCapture(bundle, {
      target: differentTarget.url,
      mode: 'exact-response-body',
    });
    expect(report.summary.failed).toBe(1);
    expect(report.results[0].comparison?.firstDiffByteOffset).toBe(11);
  });

  it('compares semantic SSE with volatile pointers', async () => {
    const sse = (id: string): string =>
      `event: message_start\ndata: {"id":"${id}","type":"message_start"}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n`;
    const original = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(sse('msg_original'));
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/v1/messages', proxyUrl), { method: 'POST', body: '{}' })).arrayBuffer();
    });

    const replayTarget = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(sse('msg_replayed'));
    });

    const failing = await replayCapture(bundle, {
      target: replayTarget.url,
      mode: 'semantic-sse-response',
    });
    expect(failing.summary.failed).toBe(1);
    expect(failing.results[0].comparison?.firstDiffEvent?.pointer).toBe('/id');

    const passing = await replayCapture(bundle, {
      target: replayTarget.url,
      mode: 'semantic-sse-response',
      normalization: { ignorePointers: ['/id'] },
    });
    expect(passing.summary.passed).toBe(1);
    expect(passing.results[0].normalizationApplied).toContain('ignore-pointers:/id');
  });

  it('reports status mismatches', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/s', proxyUrl))).arrayBuffer();
    });
    const errorTarget = await startServer((_req, res) => {
      res.writeHead(500);
      res.end('boom');
    });
    const report = await replayCapture(bundle, { target: errorTarget.url, mode: 'status-only' });
    expect(report.summary.failed).toBe(1);
    expect(report.results[0].statusMatch).toBe(false);
    expect(report.results[0].replayedStatus).toBe(500);
  });

  it('errors on unsupported comparison modes instead of skipping', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/m', proxyUrl))).arrayBuffer();
    });
    await expect(
      replayCapture(bundle, { target: original.url, mode: 'bogus-mode' as never })
    ).rejects.toThrow(/unsupported/i);
  });

  it('records transport errors per exchange', async () => {
    const original = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
    const bundle = await captureOne(original.url, async (proxyUrl) => {
      await (await fetch(new URL('/e', proxyUrl))).arrayBuffer();
    });
    const report = await replayCapture(bundle, {
      target: 'http://127.0.0.1:1',
      mode: 'status-only',
    });
    expect(report.summary.errors).toBe(1);
    expect(report.results[0].transportSuccess).toBe(false);
    expect(report.results[0].error).toBeTruthy();
  });
});

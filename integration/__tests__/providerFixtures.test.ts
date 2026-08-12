/**
 * Provider-shaped golden fixtures: synthetic local upstreams speaking the
 * Anthropic Messages, OpenAI Responses, and OpenAI Chat Completions SSE
 * protocols. Real coding-harness traffic belongs in the consuming repo.
 */
import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';
import { startCaptureSession } from '../../src/capture/index.js';
import { replayCapture } from '../../src/replay/index.js';

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()?.();
  }
});

function tmpdir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-golden-'));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const ANTHROPIC_SSE = [
  'event: message_start',
  'data: {"type":"message_start","message":{"id":"msg_01","model":"claude-3"}}',
  '',
  'event: content_block_start',
  'data: {"type":"content_block_start","index":0}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}',
  '',
  'event: content_block_stop',
  'data: {"type":"content_block_stop","index":0}',
  '',
  'event: message_delta',
  'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}',
  '',
  'event: message_stop',
  'data: {"type":"message_stop"}',
  '',
  '',
].join('\n');

const OPENAI_RESPONSES_SSE = [
  'event: response.created',
  'data: {"type":"response.created","response":{"id":"resp_01"}}',
  '',
  'event: response.output_text.delta',
  'data: {"type":"response.output_text.delta","delta":"Hello"}',
  '',
  'event: response.completed',
  'data: {"type":"response.completed","response":{"id":"resp_01","status":"completed"}}',
  '',
  '',
].join('\n');

const CHAT_COMPLETIONS_SSE = [
  'data: {"id":"chatcmpl-01","choices":[{"delta":{"role":"assistant"},"index":0}]}',
  '',
  'data: {"id":"chatcmpl-01","choices":[{"delta":{"content":"Hello"},"index":0}]}',
  '',
  'data: {"id":"chatcmpl-01","choices":[{"delta":{},"finish_reason":"stop","index":0}]}',
  '',
  'data: [DONE]',
  '',
  '',
].join('\n');

async function startProviderUpstream(): Promise<{ origin: string; close: () => void }> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = req.url ?? '';
      if (url.startsWith('/v1/messages/count_tokens')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"input_tokens":42}');
      } else if (url.startsWith('/v1/messages')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(ANTHROPIC_SSE);
      } else if (url.startsWith('/v1/responses')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(OPENAI_RESPONSES_SSE);
      } else if (url.startsWith('/v1/chat/completions')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(CHAT_COMPLETIONS_SSE);
      } else if (url.startsWith('/v1/models')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"data":[{"id":"claude-3"}]}');
      } else {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end('{"error":"not found"}');
      }
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  const close = (): void => void server.close();
  cleanups.push(close);
  return { origin: `http://127.0.0.1:${port}`, close };
}

describe('provider-shaped golden fixtures', () => {
  it('captures a full provider-shaped session and replays it green', async () => {
    const upstream = await startProviderUpstream();
    const session = await startCaptureSession({ target: upstream.origin, mode: 'exact' });
    cleanups.push(() => session.close());

    const post = (pathname: string, body: string): Promise<Response> =>
      fetch(new URL(pathname, session.url), {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'sk-ant-fake-key-for-test',
          'anthropic-version': '2023-06-01',
        },
        body,
      });

    await (
      await post('/v1/messages/count_tokens', '{"model":"claude-3","messages":[]}')
    ).arrayBuffer();
    await (
      await post(
        '/v1/messages',
        '{"model":"claude-3","stream":true,"messages":[{"role":"user","content":"hi"}]}'
      )
    ).arrayBuffer();
    await (
      await post('/v1/responses', '{"model":"gpt-4o","stream":true,"input":"hi"}')
    ).arrayBuffer();
    await (
      await post('/v1/chat/completions', '{"model":"gpt-4o","stream":true,"messages":[]}')
    ).arrayBuffer();
    await (await fetch(new URL('/v1/models', session.url))).arrayBuffer();
    await session.waitForIdle();

    const exchanges = session.exchanges();
    expect(exchanges).toHaveLength(5);
    const bySeq = new Map(exchanges.map((e) => [e.request.path.split('?')[0], e]));
    expect(bySeq.get('/v1/messages')?.response.stream.terminalMarker).toBe('message_stop');
    expect(bySeq.get('/v1/responses')?.response.stream.terminalMarker).toBe('response.completed');
    expect(bySeq.get('/v1/chat/completions')?.response.stream.terminalMarker).toBe('[DONE]');
    expect(bySeq.get('/v1/messages/count_tokens')?.response.stream.kind).toBe('buffered');

    // x-api-key must be redacted everywhere
    const serialized = JSON.stringify(exchanges);
    expect(serialized).not.toContain('sk-ant-fake-key-for-test');

    const out = tmpdir();
    const { bundle } = await session.export({ output: path.join(out, 'capture') });

    // Replay the whole capture against the same upstream shape: exact bytes.
    const replayUpstream = await startProviderUpstream();
    const report = await replayCapture(bundle, {
      target: replayUpstream.origin,
      mode: 'exact-response-body',
    });
    expect(report.summary.passed).toBe(5);

    // And semantic SSE mode also passes.
    const sseReport = await replayCapture(bundle, {
      target: replayUpstream.origin,
      mode: 'semantic-sse-response',
    });
    expect(sseReport.summary.passed).toBe(5);
  });
});

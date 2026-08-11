import { describe, it, expect } from 'vitest';
import { SseParser, parseSseBody } from '../sse.js';

describe('SseParser', () => {
  it('detects OpenAI chat completions [DONE] terminal', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('data: {"id":"1"}\n\ndata: [DONE]\n\n'));
    parser.end();
    expect(parser.terminalMarker).toBe('[DONE]');
    expect(parser.parsedEvents).toHaveLength(2);
  });

  it('detects Anthropic message_stop terminal', () => {
    const body = [
      'event: message_start',
      'data: {"type":"message_start"}',
      '',
      'event: content_block_delta',
      'data: {"type":"content_block_delta"}',
      '',
      'event: message_stop',
      'data: {"type":"message_stop"}',
      '',
      '',
    ].join('\n');
    const parser = new SseParser();
    parser.feed(Buffer.from(body));
    parser.end();
    expect(parser.terminalMarker).toBe('message_stop');
  });

  it('detects OpenAI Responses response.completed terminal', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('event: response.completed\ndata: {"type":"response.completed"}\n\n'));
    parser.end();
    expect(parser.terminalMarker).toBe('response.completed');
  });

  it('detects response.failed and response.incomplete', () => {
    for (const name of ['response.failed', 'response.incomplete']) {
      const parser = new SseParser();
      parser.feed(Buffer.from(`event: ${name}\ndata: {}\n\n`));
      parser.end();
      expect(parser.terminalMarker).toBe(name);
    }
  });

  it('detects Anthropic error event as terminal', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('event: error\ndata: {"type":"overloaded_error"}\n\n'));
    parser.end();
    expect(parser.terminalMarker).toBe('error');
  });

  it('reports no terminal for a truncated stream', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('data: {"partial":true}\n\ndata: {"more"'));
    parser.end();
    expect(parser.terminalMarker).toBeNull();
  });

  it('handles events split across chunk boundaries', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('data: [D'));
    parser.feed(Buffer.from('ONE]\n'));
    parser.feed(Buffer.from('\n'));
    parser.end();
    expect(parser.terminalMarker).toBe('[DONE]');
  });

  it('handles CRLF separators', () => {
    const parser = new SseParser();
    parser.feed(Buffer.from('data: [DONE]\r\n\r\n'));
    parser.end();
    expect(parser.terminalMarker).toBe('[DONE]');
  });

  it('joins multi-line data fields', () => {
    const events = parseSseBody(Buffer.from('data: line1\ndata: line2\n\n'));
    expect(events[0].data).toBe('line1\nline2');
  });

  it('ignores comment lines', () => {
    const events = parseSseBody(Buffer.from(': keepalive\n\ndata: x\n\n'));
    expect(events).toHaveLength(1);
    expect(events[0].data).toBe('x');
  });
});

/**
 * Incremental SSE analysis over a *copy* of the response stream. The stream
 * delivered to the client is never rewritten; this only observes event
 * boundaries to find protocol-aware terminal markers.
 */

export interface SseEvent {
  event: string | null;
  data: string;
}

/** Terminal markers recognized across provider streaming protocols. */
export function terminalMarkerFor(event: SseEvent): string | null {
  // OpenAI Chat Completions: `data: [DONE]`
  if (event.data.trim() === '[DONE]') {
    return '[DONE]';
  }
  // Anthropic Messages: `event: message_stop`
  if (event.event === 'message_stop') {
    return 'message_stop';
  }
  // Anthropic error event terminates the stream
  if (event.event === 'error') {
    return 'error';
  }
  // OpenAI Responses API: `event: response.completed` / `response.failed` /
  // `response.incomplete`
  if (
    event.event === 'response.completed' ||
    event.event === 'response.failed' ||
    event.event === 'response.incomplete'
  ) {
    return event.event;
  }
  return null;
}

/**
 * Incremental SSE parser. Feed raw bytes; complete events are surfaced as
 * they are terminated by a blank line. Handles \n, \r\n, and \r separators
 * and multi-line data fields per the SSE spec.
 */
export class SseParser {
  private buffer = '';
  private readonly decoder = new TextDecoder('utf-8');
  private readonly events: SseEvent[] = [];
  private terminal: string | null = null;

  feed(chunk: Buffer): void {
    // Streaming decode: a multi-byte UTF-8 sequence split across chunks
    // must not decode to U+FFFD halves.
    this.buffer += this.decoder.decode(chunk, { stream: true });
    this.drain(false);
  }

  end(): void {
    this.buffer += this.decoder.decode();
    this.drain(true);
  }

  get parsedEvents(): readonly SseEvent[] {
    return this.events;
  }

  get terminalMarker(): string | null {
    return this.terminal;
  }

  private drain(flush: boolean): void {
    // A CRLF pair split across chunks must not be treated as a bare CR
    // separator: when not flushing, hold back a trailing CR until the next
    // chunk reveals whether an LF follows.
    let working = this.buffer;
    let heldCr = '';
    if (!flush && working.endsWith('\r')) {
      working = working.slice(0, -1);
      heldCr = '\r';
    }
    // Normalize separators for boundary detection only (analysis copy).
    const normalized = working.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const parts = normalized.split('\n\n');
    const complete = flush ? parts : parts.slice(0, -1);
    this.buffer = flush ? '' : (parts[parts.length - 1] ?? '') + heldCr;
    for (const block of complete) {
      if (block.trim().length === 0) {
        continue;
      }
      const event = parseEventBlock(block);
      if (event) {
        this.events.push(event);
        const marker = terminalMarkerFor(event);
        if (marker && this.terminal === null) {
          this.terminal = marker;
        }
      }
    }
  }
}

function parseEventBlock(block: string): SseEvent | null {
  let eventName: string | null = null;
  const dataLines: string[] = [];
  let sawField = false;
  for (const line of block.split('\n')) {
    if (line.startsWith(':')) {
      continue; // comment
    }
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) {
      value = value.slice(1);
    }
    if (field === 'event') {
      eventName = value;
      sawField = true;
    } else if (field === 'data') {
      dataLines.push(value);
      sawField = true;
    } else if (field === 'id' || field === 'retry') {
      sawField = true;
    }
  }
  if (!sawField) {
    return null;
  }
  return { event: eventName, data: dataLines.join('\n') };
}

/** Parse a complete SSE body into events (used by replay comparison). */
export function parseSseBody(body: Buffer): SseEvent[] {
  const parser = new SseParser();
  parser.feed(body);
  parser.end();
  return [...parser.parsedEvents];
}

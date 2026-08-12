import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { writeBundle, loadBundle, makeCapturedBody } from '../index.js';
import { sanitizeBundle } from '../sanitize.js';
import { EXCHANGE_SCHEMA_VERSION, type CapturedExchange } from '../../capture/types.js';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-sanitize-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function writeDirtyBundle(
  input: string,
  options: { headerValues?: Record<string, string[]>; requestBody?: string; path?: string } = {}
): void {
  const bodies = new Map<string, Buffer>();
  const exchange: CapturedExchange = {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence: 0,
    startedAt: '2025-01-01T00:00:00.000Z',
    durationMs: 5,
    request: {
      method: 'POST',
      path: options.path ?? '/v1/messages',
      httpVersion: '1.1',
      headers: {
        values: options.headerValues ?? { 'content-type': ['application/json'] },
        redacted: [],
      },
      body: makeCapturedBody(
        Buffer.from(options.requestBody ?? '{"model":"m"}'),
        'application/json',
        null,
        bodies
      ),
    },
    response: {
      status: 200,
      statusText: 'OK',
      httpVersion: '1.1',
      headers: { values: {}, redacted: [] },
      body: makeCapturedBody(Buffer.from('{"ok":true}'), 'application/json', null, bodies),
      stream: {
        kind: 'buffered',
        completed: true,
        clientAborted: false,
        upstreamAborted: false,
        terminalMarker: null,
        error: null,
      },
    },
    failure: null,
    validation: null,
  };
  writeBundle(input, {
    manifest: {
      arbiterVersion: '1.1.0',
      mode: 'observe',
      targetOrigin: 'https://api.example.com',
      startedAt: '2025-01-01T00:00:00.000Z',
      completedAt: '2025-01-01T00:01:00.000Z',
      redaction: { redactHeaders: [], allowQuery: [] },
    },
    exchanges: [exchange],
    bodies,
  });
}

describe('sanitizeBundle', () => {
  it('re-applies redaction to headers and query values', () => {
    const input = path.join(dir, 'in');
    writeDirtyBundle(input, {
      headerValues: {
        'content-type': ['application/json'],
        authorization: ['Bearer leaked-credential'],
      },
      path: '/v1/messages?api_key=leaked-query',
    });
    const result = sanitizeBundle(input, { output: path.join(dir, 'out') });
    const serialized = JSON.stringify(result.bundle.exchanges);
    expect(serialized).not.toContain('leaked-credential');
    expect(serialized).not.toContain('leaked-query');
    expect(result.bundle.exchanges[0].request.headers.redacted).toContain('authorization');
  });

  it('fails when bodies contain rejected secrets', () => {
    const input = path.join(dir, 'in');
    writeDirtyBundle(input, { requestBody: '{"note":"key is topsecret-body-value"}' });
    expect(() =>
      sanitizeBundle(input, {
        output: path.join(dir, 'out'),
        rejectSecrets: ['topsecret-body-value'],
      })
    ).toThrow(/secret scan failed/i);
    // Failure must not leave a partial output bundle behind
    expect(fs.existsSync(path.join(dir, 'out', 'manifest.json'))).toBe(false);
  });

  it('never edits in place', () => {
    const input = path.join(dir, 'in');
    writeDirtyBundle(input);
    expect(() => sanitizeBundle(input, { output: input })).toThrow(/in place/i);
  });

  it('refuses a non-empty output directory', () => {
    const input = path.join(dir, 'in');
    writeDirtyBundle(input);
    const out = path.join(dir, 'out');
    fs.mkdirSync(out);
    fs.writeFileSync(path.join(out, 'existing.txt'), 'x');
    expect(() => sanitizeBundle(input, { output: out })).toThrow(/not empty/i);
  });

  it('produces a loadable deterministic bundle', () => {
    const input = path.join(dir, 'in');
    writeDirtyBundle(input);
    sanitizeBundle(input, { output: path.join(dir, 'out1') });
    sanitizeBundle(input, { output: path.join(dir, 'out2') });
    expect(fs.readFileSync(path.join(dir, 'out1', 'exchanges.ndjson'))).toEqual(
      fs.readFileSync(path.join(dir, 'out2', 'exchanges.ndjson'))
    );
    const reloaded = loadBundle(path.join(dir, 'out1'));
    expect(reloaded.exchanges).toHaveLength(1);
  });
});

/**
 * Hostile-input tests: loadBundle must reject malformed, oversized, and
 * path-escaping bundles outright. These bundles are hand-crafted on disk,
 * not produced through writeBundle.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadBundle, writeBundle, makeCapturedBody, BUNDLE_LIMITS } from '../index.js';
import { EXCHANGE_SCHEMA_VERSION, type CapturedExchange } from '../../capture/types.js';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-hostile-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function validExchange(bodies: Map<string, Buffer>, sequence = 0): CapturedExchange {
  return {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence,
    startedAt: '2025-01-01T00:00:00.000Z',
    durationMs: 5,
    request: {
      method: 'POST',
      path: '/v1/x',
      httpVersion: '1.1',
      headers: { values: { 'content-type': ['application/json'] }, redacted: [] },
      body: makeCapturedBody(Buffer.from('{}'), 'application/json', null, bodies),
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
}

function writeValidBundle(
  target: string,
  exchanges?: CapturedExchange[],
  bodies: Map<string, Buffer> = new Map<string, Buffer>()
): void {
  writeBundle(target, {
    manifest: {
      arbiterVersion: '1.1.0',
      mode: 'exact',
      targetOrigin: 'https://api.example.com',
      startedAt: '2025-01-01T00:00:00.000Z',
      completedAt: '2025-01-01T00:01:00.000Z',
      redaction: { redactHeaders: [], allowQuery: [] },
    },
    exchanges: exchanges ?? [validExchange(bodies)],
    bodies,
  });
}

/** Patch a single exchange line in an existing valid bundle (digest bypassed). */
function tamperExchangeLine(bundleDir: string, mutate: (parsed: any) => void): void {
  const file = path.join(bundleDir, 'exchanges.ndjson');
  const lines = fs.readFileSync(file, 'utf-8').trim().split('\n');
  const parsed = JSON.parse(lines[0]);
  mutate(parsed);
  fs.writeFileSync(
    file,
    lines.map((_, i) => (i === 0 ? JSON.stringify(parsed) : lines[i])).join('\n') + '\n'
  );
}

describe('malicious bundle rejection', () => {
  it('rejects non-object manifest and invalid manifest JSON', () => {
    const bundle = path.join(dir, 'b');
    writeValidBundle(bundle);
    fs.writeFileSync(path.join(bundle, 'manifest.json'), '"just a string"');
    expect(() => loadBundle(bundle)).toThrow(/expected an object/);
    fs.writeFileSync(path.join(bundle, 'manifest.json'), 'not json at all');
    expect(() => loadBundle(bundle)).toThrow(/not valid JSON/);
  });

  it('rejects a manifest exceeding the size bound', () => {
    const bundle = path.join(dir, 'b');
    writeValidBundle(bundle);
    fs.writeFileSync(
      path.join(bundle, 'manifest.json'),
      '{"pad":"' + 'x'.repeat(BUNDLE_LIMITS.maxManifestBytes + 10) + '"}'
    );
    expect(() => loadBundle(bundle)).toThrow(/exceeds permitted size/);
  });

  it.each([
    ['negative sequence', (e: any) => (e.sequence = -1), /out of bounds|integer/],
    ['non-finite durationMs', (e: any) => (e.durationMs = null), /finite/],
    ['non-integer sequence', (e: any) => (e.sequence = 1.5), /integer/],
    ['status out of range', (e: any) => (e.response.status = 100000), /out of bounds/],
    ['non-array header values', (e: any) => (e.request.headers.values['x'] = 'flat'), /array/],
    [
      'uppercase header name',
      (e: any) => {
        e.request.headers.values['X-Bad'] = ['v'];
      },
      /not lowercased/,
    ],
    [
      'malformed base64 body',
      (e: any) => {
        e.request.body.storage = { kind: 'inline-base64', value: '!!!not-base64!!!' };
      },
      /malformed base64/,
    ],
    [
      'base64 inconsistent with declared size',
      (e: any) => {
        e.request.body.size = 999999;
      },
      /inconsistent with declared size/,
    ],
    [
      'unknown storage kind',
      (e: any) => {
        e.request.body.storage = { kind: 'network-url', url: 'http://evil' };
      },
      /unknown kind/,
    ],
    [
      'non-content-addressed blob path',
      (e: any) => {
        e.request.body.storage = { kind: 'blob', path: 'bodies/../../etc/passwd' };
      },
      /not content-addressed/,
    ],
    ['bad sha256', (e: any) => (e.request.body.sha256 = 'zz'), /sha256/],
    ['unknown stream kind', (e: any) => (e.response.stream.kind = 'quantum'), /unknown kind/],
    ['non-boolean stream flag', (e: any) => (e.response.stream.completed = 'yes'), /boolean/],
    [
      'unknown failure stage',
      (e: any) => (e.failure = { stage: 'other', message: 'x' }),
      /unknown stage/,
    ],
  ])('rejects %s', (_name, mutate, pattern) => {
    const bundle = path.join(dir, 'b');
    writeValidBundle(bundle);
    tamperExchangeLine(bundle, mutate);
    expect(() => loadBundle(bundle)).toThrow(pattern);
    fs.rmSync(bundle, { recursive: true, force: true });
  });

  it('rejects duplicate and out-of-order sequences', () => {
    const bodies = new Map<string, Buffer>();
    const a = validExchange(bodies, 0);
    const b = validExchange(bodies, 0); // duplicate
    const bundle = path.join(dir, 'dup');
    // writeBundle sorts, so hand-write the NDJSON with the duplicate intact.
    writeValidBundle(bundle, [a]);
    const file = path.join(bundle, 'exchanges.ndjson');
    const line = fs.readFileSync(file, 'utf-8').trim();
    fs.writeFileSync(file, line + '\n' + line + '\n');
    expect(() => loadBundle(bundle)).toThrow(/duplicate or out-of-order/);

    const bundle2 = path.join(dir, 'ooo');
    writeValidBundle(bundle2, [validExchange(bodies, 0)]);
    const file2 = path.join(bundle2, 'exchanges.ndjson');
    const parsed0 = JSON.parse(fs.readFileSync(file2, 'utf-8').trim());
    const parsed1 = { ...parsed0, sequence: 5 };
    fs.writeFileSync(file2, JSON.stringify(parsed1) + '\n' + JSON.stringify(parsed0) + '\n');
    expect(() => loadBundle(bundle2)).toThrow(/duplicate or out-of-order/);
  });

  it('rejects a symlinked intermediate bodies/ directory', () => {
    const bundle = path.join(dir, 'b');
    const bodies = new Map<string, Buffer>();
    const big = Buffer.alloc(9000, 0x42); // forces a blob body
    const e1 = validExchange(bodies, 0);
    e1.response.body = makeCapturedBody(big, 'application/octet-stream', null, bodies);
    writeValidBundle(bundle, [e1], bodies);
    // Replace bodies/ with a symlink to an outside directory holding the blob.
    const outside = path.join(dir, 'outside');
    fs.mkdirSync(outside);
    for (const f of fs.readdirSync(path.join(bundle, 'bodies'))) {
      fs.copyFileSync(path.join(bundle, 'bodies', f), path.join(outside, f));
    }
    fs.rmSync(path.join(bundle, 'bodies'), { recursive: true });
    fs.symlinkSync(outside, path.join(bundle, 'bodies'));

    const loaded = loadBundle(bundle); // manifest/exchanges are still fine
    const blobExchange = loaded.exchanges[0];
    expect(() => loaded.readBody(blobExchange.response.body)).toThrow(/symlinked bundle path/i);
  });

  it('rejects a symlinked leaf blob file', () => {
    const bundle = path.join(dir, 'b');
    const bodies = new Map<string, Buffer>();
    const big = Buffer.alloc(9000, 0x43);
    const e2 = validExchange(bodies, 0);
    e2.response.body = makeCapturedBody(big, 'application/octet-stream', null, bodies);
    writeValidBundle(bundle, [e2], bodies);
    const blobName = fs.readdirSync(path.join(bundle, 'bodies'))[0];
    const target = path.join(dir, 'outside.bin');
    fs.copyFileSync(path.join(bundle, 'bodies', blobName), target);
    fs.unlinkSync(path.join(bundle, 'bodies', blobName));
    fs.symlinkSync(target, path.join(bundle, 'bodies', blobName));

    const loaded = loadBundle(bundle);
    expect(() => loaded.readBody(loaded.exchanges[0].response.body)).toThrow(/symlink/i);
  });

  it('rejects blob files larger than the declared body size', () => {
    const bundle = path.join(dir, 'b');
    const bodies = new Map<string, Buffer>();
    const big = Buffer.alloc(9000, 0x44);
    const e3 = validExchange(bodies, 0);
    e3.response.body = makeCapturedBody(big, 'application/octet-stream', null, bodies);
    writeValidBundle(bundle, [e3], bodies);
    const blobName = fs.readdirSync(path.join(bundle, 'bodies'))[0];
    fs.appendFileSync(path.join(bundle, 'bodies', blobName), Buffer.alloc(1024));
    const loaded = loadBundle(bundle);
    expect(() => loaded.readBody(loaded.exchanges[0].response.body)).toThrow(
      /exceeds permitted size/
    );
  });

  it('rejects exchange counts above the bound without allocating', () => {
    const bundle = path.join(dir, 'b');
    writeValidBundle(bundle);
    const manifest = JSON.parse(fs.readFileSync(path.join(bundle, 'manifest.json'), 'utf-8'));
    manifest.exchangeCount = BUNDLE_LIMITS.maxExchanges + 1;
    fs.writeFileSync(path.join(bundle, 'manifest.json'), JSON.stringify(manifest));
    expect(() => loadBundle(bundle)).toThrow(/out of bounds/);
  });
});

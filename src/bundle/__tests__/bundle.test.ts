import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  writeBundle,
  loadBundle,
  bundleDigest,
  makeCapturedBody,
  safeJoin,
  sha256Hex,
  stableStringify,
  INLINE_BODY_LIMIT,
} from '../index.js';
import { EXCHANGE_SCHEMA_VERSION, type CapturedExchange } from '../../capture/types.js';

function makeExchange(
  sequence: number,
  bodies: Map<string, Buffer>,
  requestBytes = Buffer.from('{"a":1}'),
  responseBytes = Buffer.from('{"ok":true}')
): CapturedExchange {
  return {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence,
    startedAt: '2025-01-01T00:00:00.000Z',
    durationMs: 12,
    request: {
      method: 'POST',
      path: '/v1/messages',
      httpVersion: '1.1',
      headers: { values: { 'content-type': ['application/json'] }, redacted: ['authorization'] },
      body: makeCapturedBody(requestBytes, 'application/json', null, bodies),
    },
    response: {
      status: 200,
      statusText: 'OK',
      httpVersion: '1.1',
      headers: { values: { 'content-type': ['application/json'] }, redacted: [] },
      body: makeCapturedBody(responseBytes, 'application/json', null, bodies),
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

const manifestBase = {
  arbiterVersion: '1.1.0',
  mode: 'exact' as const,
  targetOrigin: 'https://api.example.com',
  startedAt: '2025-01-01T00:00:00.000Z',
  completedAt: '2025-01-01T00:01:00.000Z',
  redaction: { redactHeaders: [], allowQuery: [] },
};

describe('bundle write/load', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-bundle-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips exchanges and body bytes', () => {
    const bodies = new Map<string, Buffer>();
    const big = Buffer.alloc(INLINE_BODY_LIMIT + 100, 0xab);
    const exchange = makeExchange(0, bodies, Buffer.from('{ "keep":  "whitespace" }'), big);
    writeBundle(path.join(dir, 'capture'), {
      manifest: manifestBase,
      exchanges: [exchange],
      bodies,
    });

    const bundle = loadBundle(path.join(dir, 'capture'));
    expect(bundle.exchanges).toHaveLength(1);
    expect(bundle.readBody(bundle.exchanges[0].request.body).toString('utf-8')).toBe(
      '{ "keep":  "whitespace" }'
    );
    expect(bundle.readBody(bundle.exchanges[0].response.body).equals(big)).toBe(true);
    expect(bundle.manifest.exchangeCount).toBe(1);
    expect(bundle.manifest.bundleDigest).toBe(bundleDigest([exchange]));
  });

  it('is deterministic: identical content yields identical files, including body blobs', () => {
    const bigRequest = Buffer.alloc(INLINE_BODY_LIMIT + 64, 0x5a);
    const bigResponse = Buffer.alloc(INLINE_BODY_LIMIT + 128, 0xa5);
    const write = (target: string): void => {
      const bodies = new Map<string, Buffer>();
      const exchanges = [makeExchange(0, bodies, bigRequest, bigResponse), makeExchange(1, bodies)];
      writeBundle(target, { manifest: manifestBase, exchanges, bodies });
    };
    write(path.join(dir, 'a'));
    write(path.join(dir, 'b'));
    for (const file of ['manifest.json', 'exchanges.ndjson']) {
      expect(fs.readFileSync(path.join(dir, 'a', file))).toEqual(
        fs.readFileSync(path.join(dir, 'b', file))
      );
    }
    // The content-addressed body files must match too: same names, same bytes.
    const bodiesA = fs.readdirSync(path.join(dir, 'a', 'bodies')).sort();
    const bodiesB = fs.readdirSync(path.join(dir, 'b', 'bodies')).sort();
    expect(bodiesA).toEqual(bodiesB);
    expect(bodiesA.length).toBeGreaterThanOrEqual(2);
    for (const name of bodiesA) {
      expect(fs.readFileSync(path.join(dir, 'a', 'bodies', name))).toEqual(
        fs.readFileSync(path.join(dir, 'b', 'bodies', name))
      );
    }
  });

  it('excludes timing provenance from the bundle digest', () => {
    const bodies = new Map<string, Buffer>();
    const a = makeExchange(0, bodies);
    const b = { ...a, startedAt: '2030-06-06T06:06:06.000Z', durationMs: 9999 };
    expect(bundleDigest([a])).toBe(bundleDigest([b]));
  });

  it('changes digest when body content changes', () => {
    const bodies = new Map<string, Buffer>();
    const a = makeExchange(0, bodies, Buffer.from('{"a":1}'));
    const b = makeExchange(0, bodies, Buffer.from('{"a":2}'));
    expect(bundleDigest([a])).not.toBe(bundleDigest([b]));
  });

  it('orders exchanges by sequence regardless of input order', () => {
    const bodies = new Map<string, Buffer>();
    const exchanges = [makeExchange(1, bodies), makeExchange(0, bodies)];
    writeBundle(path.join(dir, 'capture'), { manifest: manifestBase, exchanges, bodies });
    const bundle = loadBundle(path.join(dir, 'capture'));
    expect(bundle.exchanges.map((e) => e.sequence)).toEqual([0, 1]);
  });

  it('rejects tampered exchanges on load', () => {
    const bodies = new Map<string, Buffer>();
    writeBundle(path.join(dir, 'capture'), {
      manifest: manifestBase,
      exchanges: [makeExchange(0, bodies)],
      bodies,
    });
    const file = path.join(dir, 'capture', 'exchanges.ndjson');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf-8').replace('"status":200', '"status":201'));
    expect(() => loadBundle(path.join(dir, 'capture'))).toThrow(/digest mismatch/i);
  });

  it('rejects tampered body blobs on read', () => {
    const bodies = new Map<string, Buffer>();
    const big = Buffer.alloc(INLINE_BODY_LIMIT + 10, 0x42);
    const exchange = makeExchange(0, bodies, big);
    writeBundle(path.join(dir, 'capture'), {
      manifest: manifestBase,
      exchanges: [exchange],
      bodies,
    });
    const blobPath = path.join(dir, 'capture', 'bodies', `${exchange.request.body.sha256}.bin`);
    fs.writeFileSync(blobPath, Buffer.alloc(INLINE_BODY_LIMIT + 10, 0x43));
    const bundle = loadBundle(path.join(dir, 'capture'));
    expect(() => bundle.readBody(bundle.exchanges[0].request.body)).toThrow(/digest mismatch/i);
  });

  it('refuses symlinked bundle entries', () => {
    const bodies = new Map<string, Buffer>();
    writeBundle(path.join(dir, 'capture'), {
      manifest: manifestBase,
      exchanges: [makeExchange(0, bodies)],
      bodies,
    });
    const target = path.join(dir, 'outside.json');
    fs.writeFileSync(target, '{}');
    const manifestPath = path.join(dir, 'capture', 'manifest.json');
    fs.unlinkSync(manifestPath);
    fs.symlinkSync(target, manifestPath);
    expect(() => loadBundle(path.join(dir, 'capture'))).toThrow(/symlink/i);
  });

  it('rejects non-content-addressed blob paths', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = makeExchange(0, bodies);
    exchange.request.body = {
      ...exchange.request.body,
      storage: { kind: 'blob', path: 'bodies/../../evil.bin' },
    };
    expect(() =>
      writeBundle(path.join(dir, 'capture'), {
        manifest: manifestBase,
        exchanges: [exchange],
        bodies,
      })
    ).toThrow(/content-addressed/i);
  });

  it('creates bundle directories with restricted permissions', () => {
    const bodies = new Map<string, Buffer>();
    writeBundle(path.join(dir, 'capture'), {
      manifest: manifestBase,
      exchanges: [makeExchange(0, bodies)],
      bodies,
    });
    const mode = fs.statSync(path.join(dir, 'capture')).mode & 0o777;
    expect(mode).toBe(0o700);
  });
});

describe('safeJoin', () => {
  it('rejects traversal segments', () => {
    expect(() => safeJoin('/tmp/root', '..', 'etc')).toThrow(/unsafe/i);
    expect(() => safeJoin('/tmp/root', 'a/../../b')).toThrow(/unsafe/i);
    expect(() => safeJoin('/tmp/root', '/abs')).toThrow(/unsafe/i);
  });

  it('allows normal nested segments', () => {
    expect(safeJoin('/tmp/root', 'bodies', 'abc.bin')).toBe('/tmp/root/bodies/abc.bin');
  });
});

describe('stableStringify', () => {
  it('sorts keys at every depth', () => {
    expect(stableStringify({ b: { d: 1, c: 2 }, a: 3 })).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it('preserves array order', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
  });
});

describe('makeCapturedBody', () => {
  it('inlines small bodies and blobs large ones', () => {
    const bodies = new Map<string, Buffer>();
    const small = makeCapturedBody(Buffer.from('hi'), 'text/plain', null, bodies);
    expect(small.storage.kind).toBe('inline-base64');
    expect(bodies.size).toBe(0);

    const bigBytes = Buffer.alloc(INLINE_BODY_LIMIT + 1, 1);
    const big = makeCapturedBody(bigBytes, null, null, bodies);
    expect(big.storage.kind).toBe('blob');
    expect(bodies.get(big.sha256)?.equals(bigBytes)).toBe(true);
    expect(big.sha256).toBe(sha256Hex(bigBytes));
  });
});

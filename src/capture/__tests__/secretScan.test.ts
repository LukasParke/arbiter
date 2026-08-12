import { describe, it, expect } from 'vitest';
import { scanExchanges, SecretFindingError } from '../secretScan.js';
import { makeCapturedBody } from '../../bundle/index.js';
import { EXCHANGE_SCHEMA_VERSION, type CapturedExchange } from '../types.js';

function exchangeWith(
  bodies: Map<string, Buffer>,
  overrides: {
    requestBody?: Buffer;
    responseBody?: Buffer;
    requestMediaType?: string | null;
    responseMediaType?: string | null;
    path?: string;
    headers?: Record<string, string[]>;
  } = {}
): CapturedExchange {
  return {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence: 0,
    startedAt: '2025-01-01T00:00:00.000Z',
    durationMs: 1,
    request: {
      method: 'POST',
      path: overrides.path ?? '/v1/messages',
      httpVersion: '1.1',
      headers: { values: overrides.headers ?? {}, redacted: [] },
      body: makeCapturedBody(
        overrides.requestBody ?? Buffer.from('{}'),
        overrides.requestMediaType !== undefined ? overrides.requestMediaType : 'application/json',
        null,
        bodies
      ),
    },
    response: {
      status: 200,
      statusText: 'OK',
      httpVersion: '1.1',
      headers: { values: {}, redacted: [] },
      body: makeCapturedBody(
        overrides.responseBody ?? Buffer.from('{}'),
        overrides.responseMediaType !== undefined
          ? overrides.responseMediaType
          : 'application/json',
        null,
        bodies
      ),
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

const noOptions = { rejectSecrets: [], allowBinaryMediaTypes: [] };

describe('scanExchanges', () => {
  it('finds caller-supplied exact secrets in bodies', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      requestBody: Buffer.from('{"note":"the key is hunter2-super-secret"}'),
    });
    const findings = scanExchanges([exchange], bodies, undefined, {
      ...noOptions,
      rejectSecrets: ['hunter2-super-secret'],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe('caller-rejected-secret');
    expect(findings[0].location).toContain('request body');
  });

  it('never includes the secret value in findings', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      requestBody: Buffer.from('sk-ant-api03-abcdefghijklmnop'),
    });
    const findings = scanExchanges([exchange], bodies, undefined, noOptions);
    expect(findings.length).toBeGreaterThan(0);
    expect(JSON.stringify(findings)).not.toContain('abcdefghijklmnop');
    const err = new SecretFindingError(findings);
    expect(err.message).not.toContain('abcdefghijklmnop');
  });

  it.each([
    ['anthropic key', 'sk-ant-api03-0123456789abcdef'],
    ['openai key', 'sk-proj-0123456789abcdefghijklmnop'],
    ['openrouter key', 'sk-or-v1-0123456789abcdef'],
    ['github token', 'ghp_' + 'a'.repeat(36)],
    ['aws access key', 'AKIAIOSFODNN7EXAMPLE'],
    ['google api key', 'AIza' + 'a'.repeat(35)],
    ['jwt', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV'],
    ['pem key', '-----BEGIN RSA PRIVATE KEY-----'],
    ['bearer value', 'Bearer abcdefghijklmnopqrstuvwxyz012345'],
  ])('detects %s pattern', (_name, secret) => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      requestBody: Buffer.from(JSON.stringify({ v: secret })),
    });
    const findings = scanExchanges([exchange], bodies, undefined, noOptions);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('scans header values and paths', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      headers: { 'x-debug': ['sk-ant-api03-abcdefghijk'] },
      path: '/v1/messages?leak=sk-or-v1-0123456789abc',
    });
    const findings = scanExchanges([exchange], bodies, undefined, noOptions);
    const locations = findings.map((f) => f.location).join(' ');
    expect(locations).toContain('request headers');
    expect(locations).toContain('request path');
  });

  it('scans manifest metadata', () => {
    const findings = scanExchanges(
      [],
      new Map(),
      { note: 'key sk-ant-api03-abcdefghijk' },
      noOptions
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].location).toContain('metadata');
  });

  it('flags unexpected binary bodies', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      responseBody: Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]),
      responseMediaType: 'application/octet-stream',
    });
    const findings = scanExchanges([exchange], bodies, undefined, noOptions);
    expect(findings.some((f) => f.kind.startsWith('unscannable-binary-body'))).toBe(true);
  });

  it('allows binary bodies for allowed media types', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      responseBody: Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]),
      responseMediaType: 'image/png',
    });
    const findings = scanExchanges([exchange], bodies, undefined, {
      ...noOptions,
      allowBinaryMediaTypes: ['image/'],
    });
    expect(findings).toHaveLength(0);
  });

  it('passes clean captures', () => {
    const bodies = new Map<string, Buffer>();
    const exchange = exchangeWith(bodies, {
      requestBody: Buffer.from('{"model":"claude","messages":[{"role":"user","content":"hi"}]}'),
      responseBody: Buffer.from('{"id":"msg_1","content":[]}'),
    });
    expect(scanExchanges([exchange], bodies, undefined, noOptions)).toHaveLength(0);
  });
});

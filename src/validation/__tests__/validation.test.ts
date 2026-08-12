import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  writeBundle,
  loadBundle,
  makeCapturedBody,
  type CaptureBundle,
} from '../../bundle/index.js';
import { EXCHANGE_SCHEMA_VERSION, type CapturedExchange } from '../../capture/types.js';
import {
  BasicOpenAPIValidator,
  CallbackValidator,
  CommandValidator,
  validateCapture,
} from '../index.js';

let dir: string;
let bundle: CaptureBundle;

const SPEC = `
openapi: 3.1.0
info: { title: Test, version: "1.0" }
paths:
  /v1/messages:
    post:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id: { type: string }
`;

function makeExchange(bodies: Map<string, Buffer>, responseJson: string): CapturedExchange {
  return {
    schemaVersion: EXCHANGE_SCHEMA_VERSION,
    sequence: 0,
    startedAt: '2025-01-01T00:00:00.000Z',
    durationMs: 5,
    request: {
      method: 'POST',
      path: '/v1/messages',
      httpVersion: '1.1',
      headers: { values: { 'content-type': ['application/json'] }, redacted: [] },
      body: makeCapturedBody(Buffer.from('{"model":"m"}'), 'application/json', null, bodies),
    },
    response: {
      status: 200,
      statusText: 'OK',
      httpVersion: '1.1',
      headers: { values: { 'content-type': ['application/json'] }, redacted: [] },
      body: makeCapturedBody(Buffer.from(responseJson), 'application/json', null, bodies),
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

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-validate-'));
  fs.writeFileSync(path.join(dir, 'spec.yaml'), SPEC);
  const bodies = new Map<string, Buffer>();
  writeBundle(path.join(dir, 'capture'), {
    manifest: {
      arbiterVersion: '1.1.0',
      mode: 'exact',
      targetOrigin: 'https://api.example.com',
      startedAt: '2025-01-01T00:00:00.000Z',
      completedAt: '2025-01-01T00:01:00.000Z',
      redaction: { redactHeaders: [], allowQuery: [] },
    },
    exchanges: [makeExchange(bodies, '{"missing_id":true}')],
    bodies,
  });
  bundle = loadBundle(path.join(dir, 'capture'));
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('BasicOpenAPIValidator', () => {
  it('reports schema violations from bundle exchanges', async () => {
    const validator = new BasicOpenAPIValidator(path.join(dir, 'spec.yaml'));
    const report = await validateCapture(bundle, validator);
    expect(report.valid).toBe(false);
    expect(report.violations.some((v) => v.message.includes('id'))).toBe(true);
    expect(report.violations[0].source).toBe('basic-openapi');
    expect(report.violations[0].sequence).toBe(0);
  });
});

describe('CallbackValidator', () => {
  it('runs caller-supplied validation over analysis views', async () => {
    const validator = new CallbackValidator('zod-check', {
      response: (exchange, body) => {
        const parsed = JSON.parse(body.toString('utf-8')) as Record<string, unknown>;
        if (!('id' in parsed)) {
          return [
            {
              type: 'response',
              path: exchange.request.path,
              method: exchange.request.method,
              message: 'missing id',
              source: 'zod-check',
            },
          ];
        }
        return [];
      },
    });
    const report = await validateCapture(bundle, validator);
    expect(report.valid).toBe(false);
    expect(report.violations[0].message).toBe('missing id');
  });
});

describe('CommandValidator', () => {
  it('pipes exchanges through an external command', async () => {
    const script = path.join(dir, 'validator.js');
    fs.writeFileSync(
      script,
      `let input = '';
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  const { exchange, direction } = JSON.parse(input);
  if (direction === 'response') {
    console.log(JSON.stringify([{ type: 'response', path: exchange.request.path, method: exchange.request.method, message: 'external says no', source: 'external' }]));
  } else {
    console.log('[]');
  }
});`
    );
    const validator = new CommandValidator(`node ${script}`);
    const report = await validateCapture(bundle, validator);
    expect(report.violations).toHaveLength(1);
    expect(report.violations[0].message).toBe('external says no');
  });

  it('treats non-zero exit as an error, never a skip', async () => {
    const validator = new CommandValidator('exit 2');
    await expect(validateCapture(bundle, validator)).rejects.toThrow(/code 2/);
  });
});

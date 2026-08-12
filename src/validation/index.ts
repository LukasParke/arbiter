/**
 * Contract validation adapters. Validation runs on parsed analysis views of
 * captured exchanges and never changes recorded bytes.
 */

import { spawn } from 'child_process';
import type { CaptureBundle } from '../bundle/index.js';
import type { CapturedBody, CapturedExchange } from '../capture/types.js';
import { SpecValidator } from '../validate.js';

export interface Violation {
  type: 'request' | 'response';
  path: string;
  method: string;
  message: string;
  /** Where the rule came from, e.g. "basic-openapi", "command:wiretap". */
  source: string;
  detail?: string;
}

export interface ContractValidator {
  readonly name: string;
  validateRequest(exchange: CapturedExchange, body: Buffer): Promise<Violation[]>;
  validateResponse(exchange: CapturedExchange, body: Buffer): Promise<Violation[]>;
}

export interface ValidationReport {
  validator: string;
  exchangeCount: number;
  violations: Array<Violation & { sequence: number }>;
  valid: boolean;
}

export async function validateCapture(
  bundle: CaptureBundle,
  validator: ContractValidator
): Promise<ValidationReport> {
  const violations: ValidationReport['violations'] = [];
  for (const exchange of bundle.exchanges) {
    const requestBody = bundle.readBody(exchange.request.body);
    const responseBody = bundle.readBody(exchange.response.body);
    for (const violation of await validator.validateRequest(exchange, requestBody)) {
      violations.push({ ...violation, sequence: exchange.sequence });
    }
    for (const violation of await validator.validateResponse(exchange, responseBody)) {
      violations.push({ ...violation, sequence: exchange.sequence });
    }
  }
  return {
    validator: validator.name,
    exchangeCount: bundle.exchanges.length,
    violations,
    valid: violations.length === 0,
  };
}

/**
 * The existing lightweight OpenAPI validator, adapted to the canonical
 * exchange model. Checks required parameters, documented status codes, and
 * basic response schema shapes.
 */
export class BasicOpenAPIValidator implements ContractValidator {
  readonly name = 'basic-openapi';
  private readonly validator: SpecValidator;

  constructor(specPath: string) {
    this.validator = new SpecValidator(specPath);
  }

  validateRequest(exchange: CapturedExchange): Promise<Violation[]> {
    const pathname = exchange.request.path.split('?')[0];
    const query = queryRecord(exchange.request.path);
    const headers = firstValues(exchange.request.headers.values);
    const result = this.validator.validateRequest(
      pathname,
      exchange.request.method,
      query,
      headers
    );
    return Promise.resolve(
      result.violations.map((v) => ({
        type: v.type,
        path: v.path,
        method: v.method,
        message: v.message,
        source: this.name,
        ...(v.detail !== undefined ? { detail: v.detail } : {}),
      }))
    );
  }

  validateResponse(exchange: CapturedExchange, body: Buffer): Promise<Violation[]> {
    const pathname = exchange.request.path.split('?')[0];
    const contentType = exchange.response.body.mediaType ?? '';
    const parsed = parseAnalysisJson(exchange.response.body, body);
    const result = this.validator.validateResponse(
      pathname,
      exchange.request.method,
      exchange.response.status,
      contentType,
      parsed
    );
    return Promise.resolve(
      result.violations.map((v) => ({
        type: v.type,
        path: v.path,
        method: v.method,
        message: v.message,
        source: this.name,
        ...(v.detail !== undefined ? { detail: v.detail } : {}),
      }))
    );
  }
}

/**
 * Runtime callback adapter, e.g. for curated Zod schemas covering providers
 * without official OpenAPI documents.
 */
export class CallbackValidator implements ContractValidator {
  constructor(
    public readonly name: string,
    private readonly callbacks: {
      request?: (exchange: CapturedExchange, body: Buffer) => Promise<Violation[]> | Violation[];
      response?: (exchange: CapturedExchange, body: Buffer) => Promise<Violation[]> | Violation[];
    }
  ) {}

  async validateRequest(exchange: CapturedExchange, body: Buffer): Promise<Violation[]> {
    return this.callbacks.request ? await this.callbacks.request(exchange, body) : [];
  }

  async validateResponse(exchange: CapturedExchange, body: Buffer): Promise<Violation[]> {
    return this.callbacks.response ? await this.callbacks.response(exchange, body) : [];
  }
}

/**
 * External-command adapter (e.g. WireTap). The command receives one JSON
 * document on stdin — `{ exchange, direction, bodyBase64 }` — and must print
 * a JSON array of violations on stdout. Non-zero exit is a validation error,
 * never a silent skip.
 */
export class CommandValidator implements ContractValidator {
  readonly name: string;

  constructor(
    private readonly command: string,
    private readonly timeoutMs = 60_000
  ) {
    this.name = `command:${command.split(/\s+/)[0]}`;
  }

  validateRequest(exchange: CapturedExchange, body: Buffer): Promise<Violation[]> {
    return this.run(exchange, 'request', body);
  }

  validateResponse(exchange: CapturedExchange, body: Buffer): Promise<Violation[]> {
    return this.run(exchange, 'response', body);
  }

  private run(
    exchange: CapturedExchange,
    direction: 'request' | 'response',
    body: Buffer
  ): Promise<Violation[]> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, { shell: true, stdio: ['pipe', 'pipe', 'inherit'] });
      const chunks: Buffer[] = [];
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`Validator command timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code !== 0) {
          reject(new Error(`Validator command exited with code ${String(code)}`));
          return;
        }
        try {
          const output = Buffer.concat(chunks).toString('utf-8').trim();
          const parsed: unknown = output.length > 0 ? JSON.parse(output) : [];
          if (!Array.isArray(parsed)) {
            throw new Error('Validator output is not a JSON array');
          }
          resolve(parsed as Violation[]);
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
      child.stdin.end(JSON.stringify({ exchange, direction, bodyBase64: body.toString('base64') }));
    });
  }
}

function queryRecord(pathWithQuery: string): Record<string, string> {
  const queryStart = pathWithQuery.indexOf('?');
  if (queryStart === -1) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [name, value] of new URLSearchParams(pathWithQuery.slice(queryStart + 1))) {
    out[name] = value;
  }
  return out;
}

function firstValues(values: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, headerValues] of Object.entries(values)) {
    if (headerValues.length > 0) {
      out[name] = headerValues[0];
    }
  }
  return out;
}

function parseAnalysisJson(body: CapturedBody, bytes: Buffer): unknown {
  if (body.contentEncoding !== null) {
    return undefined; // compressed canonical bytes; analysis view unavailable here
  }
  if (!(body.mediaType ?? '').includes('json')) {
    return undefined;
  }
  try {
    return JSON.parse(bytes.toString('utf-8'));
  } catch {
    return undefined;
  }
}

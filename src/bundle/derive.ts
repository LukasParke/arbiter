/**
 * Derived export views. HAR and traffic JSONL are projections of the
 * canonical exchange model, never independent storage formats.
 */

import { ARBITER_VERSION } from '../version.js';
import type { CapturedBody, CapturedExchange } from '../capture/types.js';

type BodyReader = (body: CapturedBody) => Buffer;

const TEXTUAL_MEDIA = /json|text|xml|yaml|x-www-form-urlencoded|event-stream|javascript/i;

interface HarHeader {
  name: string;
  value: string;
}

export interface HarLog {
  log: {
    version: '1.2';
    creator: { name: 'Arbiter'; version: string };
    entries: HarEntry[];
  };
}

export interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: HarHeader[];
    queryString: HarHeader[];
    postData?: { mimeType: string; text: string; encoding?: 'base64' };
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: HarHeader[];
    content: { size: number; mimeType: string; text: string; encoding?: 'base64' };
  };
}

export function exchangesToHar(
  exchanges: readonly CapturedExchange[],
  targetOrigin: string,
  readBody: BodyReader
): HarLog {
  const entries = exchanges.map((exchange): HarEntry => {
    const url = new URL(exchange.request.path, targetOrigin);
    const requestBytes = readBody(exchange.request.body);
    const responseBytes = readBody(exchange.response.body);
    const requestContent = encodeContent(requestBytes, exchange.request.body);
    const responseContent = encodeContent(responseBytes, exchange.response.body);

    return {
      startedDateTime: exchange.startedAt,
      time: exchange.durationMs,
      request: {
        method: exchange.request.method,
        url: url.toString(),
        httpVersion: `HTTP/${exchange.request.httpVersion}`,
        headers: headersToHar(exchange.request.headers.values),
        queryString: [...url.searchParams].map(([name, value]) => ({ name, value })),
        ...(requestBytes.length > 0
          ? {
              postData: {
                mimeType: exchange.request.body.mediaType ?? 'application/octet-stream',
                ...requestContent,
              },
            }
          : {}),
      },
      response: {
        status: exchange.response.status,
        statusText: exchange.response.statusText,
        httpVersion: `HTTP/${exchange.response.httpVersion}`,
        headers: headersToHar(exchange.response.headers.values),
        content: {
          size: exchange.response.body.size,
          mimeType: exchange.response.body.mediaType ?? 'application/octet-stream',
          ...responseContent,
        },
      },
    };
  });

  return {
    log: {
      version: '1.2',
      creator: { name: 'Arbiter', version: ARBITER_VERSION },
      entries,
    },
  };
}

export interface TrafficLine {
  timestamp: string;
  method: string;
  path: string;
  request_headers: Record<string, string>;
  request_body: string | null;
  response_status: number;
  response_headers: Record<string, string>;
  response_body: string | null;
}

export function exchangesToTrafficJsonl(
  exchanges: readonly CapturedExchange[],
  readBody: BodyReader
): string {
  const lines = exchanges.map((exchange) => {
    const requestBytes = readBody(exchange.request.body);
    const responseBytes = readBody(exchange.response.body);
    const line: TrafficLine = {
      timestamp: exchange.startedAt,
      method: exchange.request.method,
      path: exchange.request.path,
      request_headers: firstValues(exchange.request.headers.values),
      request_body: bodyToText(requestBytes, exchange.request.body),
      response_status: exchange.response.status,
      response_headers: firstValues(exchange.response.headers.values),
      response_body: bodyToText(responseBytes, exchange.response.body),
    };
    return JSON.stringify(line);
  });
  return lines.length > 0 ? lines.join('\n') + '\n' : '';
}

function headersToHar(values: Record<string, string[]>): HarHeader[] {
  const out: HarHeader[] = [];
  for (const [name, headerValues] of Object.entries(values)) {
    for (const value of headerValues) {
      out.push({ name, value });
    }
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

function isTextual(body: CapturedBody): boolean {
  return (
    body.contentEncoding === null && body.mediaType !== null && TEXTUAL_MEDIA.test(body.mediaType)
  );
}

function encodeContent(bytes: Buffer, body: CapturedBody): { text: string; encoding?: 'base64' } {
  if (isTextual(body)) {
    return { text: bytes.toString('utf-8') };
  }
  return { text: bytes.toString('base64'), encoding: 'base64' };
}

function bodyToText(bytes: Buffer, body: CapturedBody): string | null {
  if (bytes.length === 0) {
    return null;
  }
  return isTextual(body) ? bytes.toString('utf-8') : bytes.toString('base64');
}

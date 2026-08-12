import { describe, it, expect } from 'vitest';
import { RedactionPolicy, REDACTED_VALUE, defaultRedactionPolicy } from '../redaction.js';
import { captureHeaders, normalizeHeaders, forwardableHeaders } from '../headers.js';

describe('RedactionPolicy', () => {
  it('redacts default credential headers', () => {
    for (const name of [
      'authorization',
      'Authorization',
      'proxy-authorization',
      'cookie',
      'set-cookie',
      'x-api-key',
      'x-auth-token',
      'x-goog-api-key',
    ]) {
      expect(defaultRedactionPolicy.shouldRedactHeader(name)).toBe(true);
    }
  });

  it('redacts headers matching the sensitive pattern', () => {
    for (const name of [
      'x-openai-api-key',
      'x-session-id',
      'x-csrf-token',
      'my_secret_header',
      'x-credential',
    ]) {
      expect(defaultRedactionPolicy.shouldRedactHeader(name)).toBe(true);
    }
  });

  it('keeps ordinary headers', () => {
    for (const name of [
      'content-type',
      'accept',
      'user-agent',
      'x-request-id',
      'anthropic-version',
    ]) {
      expect(defaultRedactionPolicy.shouldRedactHeader(name)).toBe(false);
    }
  });

  it('supports custom header globs', () => {
    const policy = new RedactionPolicy({ redactHeaders: ['x-custom-*'] });
    expect(policy.shouldRedactHeader('x-custom-thing')).toBe(true);
    expect(policy.shouldRedactHeader('x-other')).toBe(false);
  });

  it('redacts query values by default while keeping names', () => {
    const redacted = defaultRedactionPolicy.redactPath('/v1/messages?api_key=supersecret&page=2');
    expect(redacted).toContain('api_key=' + REDACTED_VALUE);
    expect(redacted).toContain('page=' + REDACTED_VALUE);
    expect(redacted).not.toContain('supersecret');
  });

  it('keeps explicitly allowed query values', () => {
    const policy = new RedactionPolicy({ allowQuery: ['page'] });
    const redacted = policy.redactPath('/v1/things?page=2&token=abc');
    expect(redacted).toContain('page=2');
    expect(redacted).not.toContain('token=abc');
  });

  it('leaves paths without query untouched', () => {
    expect(defaultRedactionPolicy.redactPath('/v1/messages')).toBe('/v1/messages');
  });
});

describe('captureHeaders', () => {
  it('removes redacted values but records names as evidence', () => {
    const headers = normalizeHeaders({
      authorization: 'Bearer sk-secret-value',
      'content-type': 'application/json',
    });
    const captured = captureHeaders(headers, defaultRedactionPolicy);
    expect(captured.values['authorization']).toBeUndefined();
    expect(captured.redacted).toContain('authorization');
    expect(captured.values['content-type']).toEqual(['application/json']);
    expect(JSON.stringify(captured)).not.toContain('sk-secret-value');
  });

  it('preserves duplicate header values as arrays', () => {
    const headers = normalizeHeaders({ 'x-multi': ['a', 'b'] });
    const captured = captureHeaders(headers, defaultRedactionPolicy);
    expect(captured.values['x-multi']).toEqual(['a', 'b']);
  });
});

describe('forwardableHeaders', () => {
  it('strips hop-by-hop and framing headers', () => {
    const headers = normalizeHeaders({
      connection: 'keep-alive',
      'transfer-encoding': 'chunked',
      'content-length': '10',
      te: 'trailers',
      upgrade: 'h2c',
      accept: 'application/json',
    });
    const forwarded = forwardableHeaders(headers);
    expect(Object.keys(forwarded)).toEqual(['accept']);
  });

  it('optionally strips host', () => {
    const headers = normalizeHeaders({ host: 'localhost:1234', accept: '*/*' });
    expect(forwardableHeaders(headers, { stripHost: true })['host']).toBeUndefined();
    expect(forwardableHeaders(headers)['host']).toEqual(['localhost:1234']);
  });
});

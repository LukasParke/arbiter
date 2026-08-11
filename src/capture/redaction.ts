/**
 * Redaction policy for captured traffic.
 *
 * Values for credential-bearing headers are removed before persistence; the
 * header names are retained as evidence. Query parameter values are redacted
 * by default (names retained) unless explicitly allowed.
 */

const DEFAULT_REDACTED_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-goog-api-key',
];

const SENSITIVE_HEADER_PATTERN = /api[-_]?key|auth|credential|secret|token|cookie|session/i;

export interface RedactionPolicyOptions {
  /** Additional header names or globs (e.g. `x-custom-*`) to redact. */
  redactHeaders?: string[];
  /** Query parameter names whose values may be kept. */
  allowQuery?: string[];
}

export const REDACTED_VALUE = '__redacted__';

export class RedactionPolicy {
  private readonly extraHeaderMatchers: RegExp[];
  private readonly extraHeaderNames: string[];
  private readonly allowedQuery: Set<string>;

  constructor(options: RedactionPolicyOptions = {}) {
    this.extraHeaderNames = (options.redactHeaders ?? []).map((h) => h.toLowerCase());
    this.extraHeaderMatchers = this.extraHeaderNames.map(globToRegExp);
    this.allowedQuery = new Set((options.allowQuery ?? []).map((q) => q.toLowerCase()));
  }

  shouldRedactHeader(name: string): boolean {
    const lower = name.toLowerCase();
    if (DEFAULT_REDACTED_HEADERS.includes(lower)) {
      return true;
    }
    if (SENSITIVE_HEADER_PATTERN.test(lower)) {
      return true;
    }
    return this.extraHeaderMatchers.some((m) => m.test(lower));
  }

  shouldRedactQueryValue(name: string): boolean {
    return !this.allowedQuery.has(name.toLowerCase());
  }

  /**
   * Redact query values in a path+query string. Names are retained; values
   * are replaced with a fixed placeholder unless allowed.
   */
  redactPath(pathWithQuery: string): string {
    const queryStart = pathWithQuery.indexOf('?');
    if (queryStart === -1) {
      return pathWithQuery;
    }
    const pathname = pathWithQuery.slice(0, queryStart);
    const params = new URLSearchParams(pathWithQuery.slice(queryStart + 1));
    const out = new URLSearchParams();
    for (const [name, value] of params) {
      out.append(name, this.shouldRedactQueryValue(name) ? REDACTED_VALUE : value);
    }
    const query = out.toString();
    return query.length > 0 ? `${pathname}?${query}` : pathname;
  }

  summary(): { redactHeaders: string[]; allowQuery: string[] } {
    return {
      redactHeaders: [...DEFAULT_REDACTED_HEADERS, ...this.extraHeaderNames].sort(),
      allowQuery: [...this.allowedQuery].sort(),
    };
  }
}

export const defaultRedactionPolicy = new RedactionPolicy();

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

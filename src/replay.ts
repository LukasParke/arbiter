import fs from 'fs';
import { AuthManager } from './auth.js';

export interface TrafficEntry {
  path: string;
  method: string;
  queryParams?: string[];
  status: number;
  body?: string;
  contentType?: string;
  headers?: Array<{ name: string; value: string }>;
}

export interface ReplayResult {
  path: string;
  method: string;
  originalStatus: number;
  replayedStatus: number;
  statusMatch: boolean;
  bodyDiff?: string;
  error?: string;
  durationMs: number;
}

export interface ReplayReport {
  results: ReplayResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
    avgDurationMs: number;
  };
}

function loadTraffic(path: string): TrafficEntry[] {
  const raw = fs.readFileSync(path, 'utf-8');
  const lines = raw.split('\n').filter((l) => l.trim());
  return lines.map((l) => JSON.parse(l) as TrafficEntry);
}

export async function replayTraffic(
  trafficPath: string,
  target: string,
  authManager: AuthManager,
  options: { onlyStatus?: boolean; delay?: number } = {}
): Promise<ReplayReport> {
  const entries = loadTraffic(trafficPath);
  const results: ReplayResult[] = [];
  const baseUrl = target.replace(/\/$/, '');

  for (const entry of entries) {
    const url = new URL(entry.path, baseUrl);

    // Add auth query params
    const authParams = authManager.getQueryParams();
    for (const [key, value] of Object.entries(authParams)) {
      url.searchParams.set(key, value);
    }

    // Reconstruct original query params from stored array
    if (entry.queryParams) {
      for (const qp of entry.queryParams) {
        const [key, value] = qp.split('=');
        if (key && !url.searchParams.has(key)) {
          url.searchParams.set(key, value || '');
        }
      }
    }

    const headers: Record<string, string> = {
      ...authManager.getHeaders(),
      Accept: 'application/json',
    };

    const start = Date.now();
    let replayedStatus = 0;
    let bodyDiff: string | undefined;

    try {
      const response = await fetch(url.toString(), { method: entry.method, headers });
      replayedStatus = response.status;
      const durationMs = Date.now() - start;

      const statusMatch = replayedStatus === entry.status;

      if (!options.onlyStatus && statusMatch && entry.body && entry.contentType?.includes('json')) {
        try {
          const replayedBody = await response.text();
          const diff = compareBodies(entry.body, replayedBody);
          if (diff) {
            bodyDiff = diff;
          }
        } catch {
          // Ignore body comparison errors
        }
      }

      results.push({
        path: entry.path,
        method: entry.method,
        originalStatus: entry.status,
        replayedStatus,
        statusMatch,
        bodyDiff,
        durationMs,
      });
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      results.push({
        path: entry.path,
        method: entry.method,
        originalStatus: entry.status,
        replayedStatus: 0,
        statusMatch: false,
        error: errMsg,
        durationMs: Date.now() - start,
      });
    }

    if (options.delay && options.delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, options.delay));
    }
  }

  const total = results.length;
  const failed = results.filter((r) => !r.statusMatch && !r.error).length;
  const errors = results.filter((r) => r.error).length;
  const passed = total - failed - errors;
  const avgDurationMs =
    total > 0 ? results.reduce((sum, r) => sum + r.durationMs, 0) / total : 0;

  return {
    results,
    summary: { total, passed, failed, errors, avgDurationMs: Math.round(avgDurationMs) },
  };
}

/**
 * Compare two JSON bodies and return a diff summary if they differ in shape
 */
function compareBodies(original: string, replayed: string): string | undefined {
  try {
    const orig = JSON.parse(original) as unknown;
    const replay = JSON.parse(replayed) as unknown;

    const origType = getType(orig);
    const replayType = getType(replay);

    if (origType !== replayType) {
      return `Type mismatch: expected ${origType}, got ${replayType}`;
    }

    if (origType === 'object' && replayType === 'object') {
      const origKeys = Object.keys(orig as Record<string, unknown>);
      const replayKeys = Object.keys(replay as Record<string, unknown>);
      const missing = origKeys.filter((k) => !replayKeys.includes(k));
      const extra = replayKeys.filter((k) => !origKeys.includes(k));
      if (missing.length > 0 || extra.length > 0) {
        const parts: string[] = [];
        if (missing.length > 0) {parts.push(`missing keys: ${missing.join(', ')}`);}
        if (extra.length > 0) {parts.push(`extra keys: ${extra.join(', ')}`);}
        return `Shape diff: ${parts.join('; ')}`;
      }
    }

    return undefined;
  } catch {
    // If we can't parse, do string comparison
    if (original !== replayed) {
      return 'Body content differs (string comparison)';
    }
    return undefined;
  }
}

function getType(value: unknown): string {
  if (value === null) {return 'null';}
  if (Array.isArray(value)) {return 'array';}
  return typeof value;
}

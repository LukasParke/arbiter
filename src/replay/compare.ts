import { parseSseBody } from '../capture/sse.js';

export interface ComparisonResult {
  match: boolean;
  /** First differing byte offset (exact mode). */
  firstDiffByteOffset?: number;
  /** JSON pointer to the first differing value (semantic JSON). */
  firstDiffPointer?: string;
  /** Index and pointer of the first differing SSE event (semantic SSE). */
  firstDiffEvent?: { index: number; pointer: string | null; reason: string };
  detail?: string;
}

/** Byte-for-byte comparison reporting the first differing offset. */
export function compareExactBytes(expected: Buffer, actual: Buffer): ComparisonResult {
  const limit = Math.min(expected.length, actual.length);
  for (let i = 0; i < limit; i++) {
    if (expected[i] !== actual[i]) {
      return {
        match: false,
        firstDiffByteOffset: i,
        detail: `Byte mismatch at offset ${i}: expected 0x${expected[i].toString(16)}, got 0x${actual[i].toString(16)}`,
      };
    }
  }
  if (expected.length !== actual.length) {
    return {
      match: false,
      firstDiffByteOffset: limit,
      detail: `Length mismatch: expected ${expected.length} bytes, got ${actual.length}`,
    };
  }
  return { match: true };
}

export interface JsonNormalization {
  /** JSON pointers whose values are volatile and excluded from comparison. */
  ignorePointers?: string[];
}

/** Semantic JSON comparison after declared normalization. */
export function compareSemanticJson(
  expected: Buffer,
  actual: Buffer,
  normalization: JsonNormalization = {}
): ComparisonResult {
  let expectedValue: unknown;
  let actualValue: unknown;
  try {
    expectedValue = JSON.parse(expected.toString('utf-8'));
  } catch (err) {
    return { match: false, detail: `Expected body is not valid JSON: ${String(err)}` };
  }
  try {
    actualValue = JSON.parse(actual.toString('utf-8'));
  } catch (err) {
    return { match: false, detail: `Actual body is not valid JSON: ${String(err)}` };
  }
  const ignore = new Set(normalization.ignorePointers ?? []);
  const pointer = firstJsonDiff(expectedValue, actualValue, '', ignore);
  if (pointer !== null) {
    return {
      match: false,
      firstDiffPointer: pointer,
      detail: `JSON values differ at ${pointer || '/'}`,
    };
  }
  return { match: true };
}

export interface SseNormalization extends JsonNormalization {
  /** Compare only these event names when set. */
  eventFilter?: string[];
}

/**
 * Semantic SSE comparison: ordered events must match by name, and JSON data
 * payloads are compared semantically with declared volatile pointers.
 * Non-JSON data is compared as text.
 */
export function compareSemanticSse(
  expected: Buffer,
  actual: Buffer,
  normalization: SseNormalization = {}
): ComparisonResult {
  const filter = normalization.eventFilter ? new Set(normalization.eventFilter) : null;
  const keep = (e: { event: string | null }): boolean =>
    filter === null || (e.event !== null && filter.has(e.event));
  const allExpected = parseSseBody(expected);
  if (allExpected.length === 0) {
    // A body that yields no SSE events is not comparable in SSE mode;
    // matching it vacuously would be a false green.
    return { match: false, detail: 'Expected body contains no parseable SSE events' };
  }
  const allActual = parseSseBody(actual);
  if (allActual.length === 0) {
    return { match: false, detail: 'Actual body contains no parseable SSE events' };
  }
  const expectedEvents = allExpected.filter(keep);
  const actualEvents = allActual.filter(keep);
  const ignore = new Set(normalization.ignorePointers ?? []);

  const limit = Math.min(expectedEvents.length, actualEvents.length);
  for (let i = 0; i < limit; i++) {
    const exp = expectedEvents[i];
    const act = actualEvents[i];
    if (exp.event !== act.event) {
      return {
        match: false,
        firstDiffEvent: {
          index: i,
          pointer: null,
          reason: `event name: expected ${exp.event ?? '(none)'}, got ${act.event ?? '(none)'}`,
        },
      };
    }
    const expJson = tryParseJson(exp.data);
    const actJson = tryParseJson(act.data);
    if (expJson.ok && actJson.ok) {
      const pointer = firstJsonDiff(expJson.value, actJson.value, '', ignore);
      if (pointer !== null) {
        return {
          match: false,
          firstDiffEvent: { index: i, pointer, reason: `data JSON differs at ${pointer || '/'}` },
        };
      }
    } else if (exp.data !== act.data) {
      return {
        match: false,
        firstDiffEvent: { index: i, pointer: null, reason: 'data text differs' },
      };
    }
  }
  if (expectedEvents.length !== actualEvents.length) {
    return {
      match: false,
      firstDiffEvent: {
        index: limit,
        pointer: null,
        reason: `event count: expected ${expectedEvents.length}, got ${actualEvents.length}`,
      },
    };
  }
  return { match: true };
}

function tryParseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return { ok: false };
  }
  try {
    return { ok: true, value: JSON.parse(trimmed) };
  } catch {
    return { ok: false };
  }
}

/** Returns the JSON pointer of the first difference, or null when equal. */
export function firstJsonDiff(
  expected: unknown,
  actual: unknown,
  pointer: string,
  ignore: ReadonlySet<string>
): string | null {
  if (ignore.has(pointer)) {
    return null;
  }
  if (Array.isArray(expected) && Array.isArray(actual)) {
    const limit = Math.min(expected.length, actual.length);
    for (let i = 0; i < limit; i++) {
      const diff = firstJsonDiff(expected[i], actual[i], `${pointer}/${i}`, ignore);
      if (diff !== null) {
        return diff;
      }
    }
    if (expected.length !== actual.length) {
      return `${pointer}/${limit}`;
    }
    return null;
  }
  if (
    expected !== null &&
    actual !== null &&
    typeof expected === 'object' &&
    typeof actual === 'object' &&
    !Array.isArray(expected) &&
    !Array.isArray(actual)
  ) {
    const expectedObj = expected as Record<string, unknown>;
    const actualObj = actual as Record<string, unknown>;
    const keys = [...new Set([...Object.keys(expectedObj), ...Object.keys(actualObj)])].sort();
    for (const key of keys) {
      const child = `${pointer}/${escapePointer(key)}`;
      if (ignore.has(child)) {
        continue;
      }
      if (!(key in expectedObj) || !(key in actualObj)) {
        return child;
      }
      const diff = firstJsonDiff(expectedObj[key], actualObj[key], child, ignore);
      if (diff !== null) {
        return diff;
      }
    }
    return null;
  }
  return Object.is(expected, actual) ? null : pointer === '' ? '/' : pointer;
}

function escapePointer(key: string): string {
  return key.replace(/~/g, '~0').replace(/\//g, '~1');
}

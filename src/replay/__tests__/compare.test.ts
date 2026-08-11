import { describe, it, expect } from 'vitest';
import {
  compareExactBytes,
  compareSemanticJson,
  compareSemanticSse,
  firstJsonDiff,
} from '../compare.js';

describe('compareExactBytes', () => {
  it('matches identical buffers', () => {
    expect(compareExactBytes(Buffer.from('abc'), Buffer.from('abc')).match).toBe(true);
  });

  it('reports first differing byte offset', () => {
    const result = compareExactBytes(Buffer.from('abcdef'), Buffer.from('abcXef'));
    expect(result.match).toBe(false);
    expect(result.firstDiffByteOffset).toBe(3);
  });

  it('reports length mismatch at the shorter length', () => {
    const result = compareExactBytes(Buffer.from('abc'), Buffer.from('abcd'));
    expect(result.match).toBe(false);
    expect(result.firstDiffByteOffset).toBe(3);
  });
});

describe('compareSemanticJson', () => {
  it('ignores whitespace and key order', () => {
    const a = Buffer.from('{"b": 1, "a": [1, 2]}');
    const b = Buffer.from('{ "a":[1,2],\n"b":1 }');
    expect(compareSemanticJson(a, b).match).toBe(true);
  });

  it('reports the first differing JSON pointer', () => {
    const a = Buffer.from('{"x":{"y":[1,2,3]}}');
    const b = Buffer.from('{"x":{"y":[1,9,3]}}');
    const result = compareSemanticJson(a, b);
    expect(result.match).toBe(false);
    expect(result.firstDiffPointer).toBe('/x/y/1');
  });

  it('honors ignored pointers', () => {
    const a = Buffer.from('{"id":"one","value":1}');
    const b = Buffer.from('{"id":"two","value":1}');
    expect(compareSemanticJson(a, b, { ignorePointers: ['/id'] }).match).toBe(true);
  });

  it('fails on invalid JSON rather than skipping', () => {
    const result = compareSemanticJson(Buffer.from('not json'), Buffer.from('{}'));
    expect(result.match).toBe(false);
    expect(result.detail).toContain('not valid JSON');
  });

  it('reports missing keys', () => {
    const result = compareSemanticJson(Buffer.from('{"a":1}'), Buffer.from('{}'));
    expect(result.match).toBe(false);
    expect(result.firstDiffPointer).toBe('/a');
  });
});

describe('compareSemanticSse', () => {
  const stream = (events: string[]): Buffer => Buffer.from(events.join('\n\n') + '\n\n');

  it('matches identical event streams', () => {
    const a = stream(['event: delta\ndata: {"t":"x"}', 'data: [DONE]']);
    expect(compareSemanticSse(a, a).match).toBe(true);
  });

  it('compares JSON payloads semantically', () => {
    const a = stream(['data: {"a":1, "b":2}']);
    const b = stream(['data: {"b":2,"a":1}']);
    expect(compareSemanticSse(a, b).match).toBe(true);
  });

  it('reports first differing event with pointer', () => {
    const a = stream(['data: {"n":1}', 'data: {"n":2}']);
    const b = stream(['data: {"n":1}', 'data: {"n":3}']);
    const result = compareSemanticSse(a, b);
    expect(result.match).toBe(false);
    expect(result.firstDiffEvent?.index).toBe(1);
    expect(result.firstDiffEvent?.pointer).toBe('/n');
  });

  it('honors volatile pointers in event data', () => {
    const a = stream(['data: {"id":"a","text":"same"}']);
    const b = stream(['data: {"id":"b","text":"same"}']);
    expect(compareSemanticSse(a, b, { ignorePointers: ['/id'] }).match).toBe(true);
  });

  it('reports event name mismatches', () => {
    const a = stream(['event: message_start\ndata: {}']);
    const b = stream(['event: message_stop\ndata: {}']);
    const result = compareSemanticSse(a, b);
    expect(result.match).toBe(false);
    expect(result.firstDiffEvent?.reason).toContain('event name');
  });

  it('reports event count mismatches', () => {
    const a = stream(['data: {"n":1}', 'data: [DONE]']);
    const b = stream(['data: {"n":1}']);
    const result = compareSemanticSse(a, b);
    expect(result.match).toBe(false);
    expect(result.firstDiffEvent?.reason).toContain('event count');
  });
});

describe('firstJsonDiff', () => {
  it('escapes JSON pointer special characters', () => {
    const diff = firstJsonDiff({ 'a/b': 1 }, { 'a/b': 2 }, '', new Set());
    expect(diff).toBe('/a~1b');
  });

  it('returns null for deep equality', () => {
    expect(firstJsonDiff({ a: [{ b: null }] }, { a: [{ b: null }] }, '', new Set())).toBeNull();
  });
});

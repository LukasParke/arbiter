import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { BodySink, BodyLimitExceededError } from '../bodySink.js';

describe('BodySink', () => {
  it('accumulates bytes and computes sha256', () => {
    const sink = new BodySink(1024, 'fail');
    sink.write(Buffer.from('hello '));
    sink.write(Buffer.from('world'));
    const done = sink.finish();
    expect(done.size).toBe(11);
    expect(done.read().toString('utf-8')).toBe('hello world');
    expect(done.sha256).toBe(createHash('sha256').update('hello world').digest('hex'));
  });

  it('fails on limit crossing with fail policy', () => {
    const sink = new BodySink(4, 'fail');
    expect(() => sink.write(Buffer.from('too long'))).toThrow(BodyLimitExceededError);
  });

  it('spills to disk with spill policy and preserves bytes', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-sink-'));
    const sink = new BodySink(4, 'spill', dir);
    const payload = Buffer.from('0123456789abcdef');
    sink.write(payload.subarray(0, 8));
    sink.write(payload.subarray(8));
    const done = sink.finish();
    expect(done.read().equals(payload)).toBe(true);
    expect(done.size).toBe(16);
    const spillFiles = fs.readdirSync(dir);
    expect(spillFiles.length).toBe(1);
    const mode = fs.statSync(path.join(dir, spillFiles[0])).mode & 0o777;
    expect(mode).toBe(0o600);
    done.dispose();
    expect(fs.readdirSync(dir)).toHaveLength(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('abort removes spill files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-sink-'));
    const sink = new BodySink(2, 'spill', dir);
    sink.write(Buffer.from('spill me'));
    sink.abort();
    expect(fs.readdirSync(dir)).toHaveLength(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

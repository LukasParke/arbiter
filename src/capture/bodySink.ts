import { createHash, randomBytes } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

export type BodyLimitPolicy = 'spill' | 'fail';

/** Hard ceiling for spilled bodies: spill moves storage to disk, it does not
 * remove limits entirely. 4 GiB default. */
export const MAX_SPILLED_BODY_BYTES = 4 * 1024 * 1024 * 1024;

export class BodyLimitExceededError extends Error {
  constructor(limit: number) {
    super(`Body exceeded configured limit of ${limit} bytes`);
    this.name = 'BodyLimitExceededError';
  }
}

/**
 * Accumulates raw body bytes with incremental SHA-256. Below the limit bytes
 * stay in memory; crossing it either spills to a restricted temporary file or
 * fails the exchange, never silently truncates.
 */
export class BodySink {
  private readonly hash = createHash('sha256');
  private chunks: Buffer[] = [];
  private byteCount = 0;
  private spillPath: string | null = null;
  private spillFd: number | null = null;
  private finished = false;

  constructor(
    private readonly limit: number,
    private readonly policy: BodyLimitPolicy,
    private readonly spillDir: string = os.tmpdir(),
    private readonly spillLimit: number = MAX_SPILLED_BODY_BYTES
  ) {}

  write(chunk: Buffer): void {
    if (this.finished) {
      throw new Error('BodySink already finished');
    }
    this.hash.update(chunk);
    this.byteCount += chunk.length;
    if (this.spillFd !== null) {
      // Spill changes the storage medium, not the contract: crossing the
      // spill ceiling is still a hard failure, never silent truncation.
      if (this.byteCount > this.spillLimit) {
        this.abortWith(new BodyLimitExceededError(this.spillLimit));
      }
      fs.writeSync(this.spillFd, chunk);
      return;
    }
    this.chunks.push(chunk);
    if (this.byteCount > this.limit) {
      if (this.policy === 'fail') {
        throw new BodyLimitExceededError(this.limit);
      }
      if (this.byteCount > this.spillLimit) {
        this.abortWith(new BodyLimitExceededError(this.spillLimit));
      }
      this.spill();
    }
  }

  private abortWith(error: Error): never {
    this.abort();
    throw error;
  }

  get size(): number {
    return this.byteCount;
  }

  private spill(): void {
    fs.mkdirSync(this.spillDir, { recursive: true, mode: 0o700 });
    this.spillPath = path.join(this.spillDir, `arbiter-spill-${randomBytes(8).toString('hex')}`);
    this.spillFd = fs.openSync(this.spillPath, 'wx', 0o600);
    for (const chunk of this.chunks) {
      fs.writeSync(this.spillFd, chunk);
    }
    this.chunks = [];
  }

  /** Finalize and return the digest plus a loader for the full bytes. */
  finish(): { sha256: string; size: number; read: () => Buffer; dispose: () => void } {
    this.finished = true;
    const sha256 = this.hash.digest('hex');
    const size = this.byteCount;
    if (this.spillFd !== null) {
      fs.closeSync(this.spillFd);
      this.spillFd = null;
      const spillPath = this.spillPath as string;
      return {
        sha256,
        size,
        read: (): Buffer => fs.readFileSync(spillPath),
        dispose: (): void => {
          try {
            fs.unlinkSync(spillPath);
          } catch {
            /* already removed */
          }
        },
      };
    }
    const bytes = Buffer.concat(this.chunks);
    this.chunks = [];
    return {
      sha256,
      size,
      read: (): Buffer => bytes,
      dispose: (): void => {},
    };
  }

  abort(): void {
    if (this.finished) {
      return; // finish() already transferred ownership of the bytes
    }
    this.finished = true;
    if (this.spillFd !== null) {
      fs.closeSync(this.spillFd);
      this.spillFd = null;
    }
    if (this.spillPath !== null) {
      try {
        fs.unlinkSync(this.spillPath);
      } catch {
        /* already removed */
      }
      this.spillPath = null;
    }
    this.chunks = [];
  }
}

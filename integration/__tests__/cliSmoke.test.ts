/**
 * CLI smoke tests: run the built CLI end-to-end for capture -> sanitize ->
 * validate -> replay against local upstreams. Requires `pnpm build` output
 * in dist/ (vitest globalSetup builds are avoided; we spawn tsx-less node
 * against dist which CI produces before tests).
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, execSync, type ChildProcess } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { once } from 'events';

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'dist', 'src', 'cli.js');

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()?.();
  }
});

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    execSync('pnpm build', { cwd: ROOT, stdio: 'inherit' });
  }
}, 120_000);

function tmpdir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arbiter-cli-'));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function startUpstream(): Promise<{ origin: string }> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"id":"resp_1","ok":true}');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  cleanups.push(() => void server.close());
  const { port } = server.address() as { port: number };
  return { origin: `http://127.0.0.1:${port}` };
}

function startCli(args: string[], env: NodeJS.ProcessEnv = {}): ChildProcess {
  const child = spawn(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) {
      child.kill('SIGKILL');
    }
  });
  return child;
}

async function waitForFile(filePath: string, timeoutMs = 15_000): Promise<void> {
  const start = Date.now();
  while (!fs.existsSync(filePath)) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`Timed out waiting for ${filePath}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function waitForExit(child: ChildProcess, timeoutMs = 20_000): Promise<number> {
  if (child.exitCode !== null) {
    return child.exitCode;
  }
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CLI did not exit in time')), timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve(code ?? -1);
    });
  });
}

describe('CLI capture/replay smoke', () => {
  it('captures, exports, sanitizes, and replays through the CLI', async () => {
    const upstream = await startUpstream();
    const work = tmpdir();
    const readyFile = path.join(work, 'ready.json');
    const reportFile = path.join(work, 'capture-report.json');
    const bundleDir = path.join(work, 'capture');

    const capture = startCli([
      'capture',
      '--target',
      upstream.origin,
      '--output',
      bundleDir,
      '--exact',
      '--ready-file',
      readyFile,
      '--report',
      reportFile,
    ]);
    const stderr: Buffer[] = [];
    capture.stderr?.on('data', (c: Buffer) => stderr.push(c));

    await waitForFile(readyFile);
    const ready = JSON.parse(fs.readFileSync(readyFile, 'utf-8')) as { url: string };

    const res = await fetch(new URL('/v1/test', ready.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer sk-cli-secret' },
      body: '{"model":"m","input":"hello"}',
    });
    expect(res.status).toBe(200);
    await res.arrayBuffer();

    capture.kill('SIGTERM');
    const code = await waitForExit(capture);
    expect(code, Buffer.concat(stderr).toString()).toBe(0);

    const report = JSON.parse(fs.readFileSync(reportFile, 'utf-8')) as {
      bundle: { exchangeCount: number } | null;
      error: string | null;
    };
    expect(report.error).toBeNull();
    expect(report.bundle?.exchangeCount).toBe(1);

    // The bundle never contains the credential.
    const exchangesRaw = fs.readFileSync(path.join(bundleDir, 'exchanges.ndjson'), 'utf-8');
    expect(exchangesRaw).not.toContain('sk-cli-secret');

    // Sanitize into a new bundle.
    const sanitized = path.join(work, 'sanitized');
    const sanitize = startCli(['sanitize', bundleDir, '--output', sanitized]);
    expect(await waitForExit(sanitize)).toBe(0);
    expect(fs.existsSync(path.join(sanitized, 'manifest.json'))).toBe(true);

    // Replay the sanitized bundle against a fresh identical upstream.
    const replayUpstream = await startUpstream();
    const replayReport = path.join(work, 'replay-report.json');
    const replay = startCli([
      'replay',
      sanitized,
      '--target',
      replayUpstream.origin,
      '--mode',
      'semantic-json-response',
      '--report',
      replayReport,
      '--fail-on-diff',
    ]);
    const replayCode = await waitForExit(replay);
    expect(replayCode).toBe(0);
    const parsed = JSON.parse(fs.readFileSync(replayReport, 'utf-8')) as {
      summary: { passed: number };
    };
    expect(parsed.summary.passed).toBe(1);
  }, 60_000);

  it('fails capture export when a rejected secret env value appears in traffic', async () => {
    const upstream = await startUpstream();
    const work = tmpdir();
    const readyFile = path.join(work, 'ready.json');
    const reportFile = path.join(work, 'report.json');

    const capture = startCli(
      [
        'capture',
        '--target',
        upstream.origin,
        '--output',
        path.join(work, 'capture'),
        '--exact',
        '--ready-file',
        readyFile,
        '--report',
        reportFile,
        '--reject-secret',
        'ARBITER_SMOKE_SECRET',
      ],
      { ARBITER_SMOKE_SECRET: 'leaked-cli-secret-value' }
    );

    await waitForFile(readyFile);
    const ready = JSON.parse(fs.readFileSync(readyFile, 'utf-8')) as { url: string };
    await (
      await fetch(new URL('/v1/x', ready.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"note":"the secret is leaked-cli-secret-value"}',
      })
    ).arrayBuffer();

    capture.kill('SIGTERM');
    const code = await waitForExit(capture);
    expect(code).toBe(1);
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf-8')) as { error: string | null };
    expect(report.error).toMatch(/secret scan failed/i);
  }, 60_000);
});

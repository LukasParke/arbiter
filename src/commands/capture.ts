import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { startCaptureSession, RedactionPolicy } from '../capture/index.js';

interface CaptureCliOptions {
  target: string;
  output: string;
  port: string;
  host: string;
  exact?: boolean;
  redactHeader: string[];
  allowQuery: string[];
  rejectSecret: string[];
  allowBinaryMediaType: string[];
  maxBodyBytes: string;
  idleTimeout?: string;
  readyFile?: string;
  report?: string;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function parsePositiveInt(value: string, flag: string, opts: { allowZero?: boolean } = {}): number {
  const parsed = Number(value);
  const min = opts.allowZero ? 0 : 1;
  if (!Number.isInteger(parsed) || parsed < min) {
    console.error(chalk.red(`${flag} must be an integer >= ${min} (got ${value})`));
    process.exit(1);
  }
  return parsed;
}

export const captureCommand = new Command('capture')
  .description('Run an exact-capture proxy and export a deterministic capture bundle on shutdown')
  .requiredOption('-t, --target <url>', 'upstream API origin to proxy to')
  .requiredOption('-o, --output <dir>', 'directory to write the capture bundle to')
  .option('-p, --port <number>', 'port to listen on (0 = random)', '0')
  .option('--host <hostname>', 'hostname to bind', '127.0.0.1')
  .option('--exact', 'fail-closed exact capture semantics (recommended)')
  .option(
    '--redact-header <glob>',
    'additional header name/glob to redact (repeatable)',
    collect,
    []
  )
  .option(
    '--allow-query <name>',
    'query parameter whose value may be kept (repeatable)',
    collect,
    []
  )
  .option(
    '--reject-secret <env-name>',
    'name of an env var whose value must not appear anywhere in the bundle (repeatable)',
    collect,
    []
  )
  .option(
    '--allow-binary-media-type <prefix>',
    'media type prefix allowed to remain unscanned binary (repeatable)',
    collect,
    []
  )
  .option(
    '--max-body-bytes <n>',
    'body size limit before spilling to disk',
    String(32 * 1024 * 1024)
  )
  .option('--idle-timeout <ms>', 'shut down after this many ms without traffic')
  .option('--ready-file <path>', 'write listener metadata JSON atomically once ready')
  .option('--report <path>', 'write a machine-readable final report on shutdown')
  .action(async (options: CaptureCliOptions) => {
    const port = parsePositiveInt(options.port, '--port', { allowZero: true });
    const maxBodyBytes = parsePositiveInt(options.maxBodyBytes, '--max-body-bytes');
    const idleTimeoutMs =
      options.idleTimeout !== undefined
        ? parsePositiveInt(options.idleTimeout, '--idle-timeout')
        : undefined;

    const rejectSecrets: string[] = [];
    for (const envName of options.rejectSecret) {
      const value = process.env[envName];
      if (value === undefined || value.length === 0) {
        console.error(chalk.red(`--reject-secret ${envName}: environment variable is not set`));
        process.exit(1);
      }
      rejectSecrets.push(value);
    }

    const redaction = new RedactionPolicy({
      redactHeaders: options.redactHeader,
      allowQuery: options.allowQuery,
    });

    const session = await startCaptureSession({
      target: options.target,
      listen: { hostname: options.host, port },
      mode: options.exact ? 'exact' : 'observe',
      redaction,
      maxBodyBytes,
    });

    console.info(chalk.green('Arbiter capture proxy listening'));
    console.info(chalk.cyan(`  Proxy:  ${session.url.toString()}`));
    console.info(chalk.gray(`  Target: ${options.target}`));
    console.info(chalk.gray(`  Mode:   ${options.exact ? 'exact (fail-closed)' : 'observe'}`));

    if (options.readyFile) {
      const readyPayload = JSON.stringify({
        url: session.url.toString(),
        target: options.target,
        mode: options.exact ? 'exact' : 'observe',
        pid: process.pid,
      });
      const tmp = `${options.readyFile}.tmp`;
      fs.writeFileSync(tmp, readyPayload, { mode: 0o600 });
      fs.renameSync(tmp, options.readyFile);
    }

    let idleTimer: NodeJS.Timeout | null = null;
    const armIdle = (): void => {
      if (idleTimeoutMs === undefined) {
        return;
      }
      if (idleTimer) {
        clearTimeout(idleTimer);
      }
      idleTimer = setTimeout(() => {
        console.info(chalk.yellow('Idle timeout reached, shutting down'));
        void shutdown(0);
      }, idleTimeoutMs);
    };
    if (idleTimeoutMs !== undefined) {
      const interval = setInterval(() => {
        // Re-arm on traffic: exchanges() grows as requests settle.
        if (session.exchanges().length !== lastCount) {
          lastCount = session.exchanges().length;
          armIdle();
        }
      }, 250);
      interval.unref();
      let lastCount = 0;
      armIdle();
    }

    let shuttingDown = false;
    async function shutdown(code: number): Promise<void> {
      if (shuttingDown) {
        return;
      }
      shuttingDown = true;
      let exitCode = code;
      const report: Record<string, unknown> = {
        target: options.target,
        mode: options.exact ? 'exact' : 'observe',
        exchangeCount: session.exchanges().length,
        failures: session.failures(),
        bundle: null,
        error: null,
      };
      try {
        await session.waitForIdle();
        const { manifest } = await session.export({
          output: options.output,
          rejectSecrets,
          allowBinaryMediaTypes: options.allowBinaryMediaType,
        });
        report.bundle = {
          path: path.resolve(options.output),
          exchangeCount: manifest.exchangeCount,
          bundleDigest: manifest.bundleDigest,
        };
        console.info(
          chalk.green(`Exported ${manifest.exchangeCount} exchange(s) to ${options.output}`)
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        report.error = message;
        console.error(chalk.red('Export failed:'), message);
        exitCode = 1;
      } finally {
        await session.close();
        if (options.report) {
          const tmp = `${options.report}.tmp`;
          fs.writeFileSync(tmp, JSON.stringify(report, null, 2), { mode: 0o600 });
          fs.renameSync(tmp, options.report);
        }
        process.exit(exitCode);
      }
    }

    process.on('SIGINT', () => void shutdown(0));
    process.on('SIGTERM', () => void shutdown(0));
  });

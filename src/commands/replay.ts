import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { loadBundle } from '../bundle/index.js';
import {
  replayCapture,
  credentialProviderFromEnvMappings,
  type ReplayComparisonMode,
} from '../replay/index.js';
import { replayTraffic } from '../replay/legacy.js';
import { AuthManager } from '../auth.js';

interface ReplayCliOptions {
  input?: string;
  legacyJsonl?: boolean;
  target: string;
  mode: string;
  credentialEnv: string[];
  ignorePointer: string[];
  queryEnv: string[];
  token?: string;
  onlyStatus?: boolean;
  delay: string;
  report?: string;
  failOnDiff?: boolean;
  verbose?: boolean;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

const MODES: ReplayComparisonMode[] = [
  'status-only',
  'exact-response-body',
  'semantic-json-response',
  'semantic-sse-response',
];

export const replayCommand = new Command('replay')
  .description('Replay a capture bundle (or legacy traffic JSONL) for regression testing')
  .argument('[bundle]', 'path to a capture bundle directory')
  .option('-i, --input <path>', 'legacy alias for the capture path')
  .option('--legacy-jsonl', 'treat the input as legacy traffic JSONL instead of a bundle')
  .requiredOption('--target <url>', 'target API URL to replay against')
  .option('--mode <mode>', `comparison mode: ${MODES.join(', ')}`, 'status-only')
  .option(
    '--credential-env <mapping>',
    'ENV:header[:prefix] credential mapping (repeatable)',
    collect,
    []
  )
  .option('--ignore-pointer <pointer>', 'volatile JSON pointer to ignore (repeatable)', collect, [])
  .option(
    '--query-env <mapping>',
    'NAME:ENV replacement for a capture-redacted query value (repeatable)',
    collect,
    []
  )
  .option('--token <token>', '(legacy) authentication token for replayed requests')
  .option('--only-status', '(legacy) only compare status codes')
  .option('--delay <ms>', 'delay between requests in milliseconds', '0')
  .option('--report <path>', 'write the JSON replay report to a file')
  .option('--fail-on-diff', 'exit with code 1 if any regressions are found')
  .option('-v, --verbose', 'show details for all requests, not just failures')
  .action(async (bundleArg: string | undefined, options: ReplayCliOptions) => {
    const input = bundleArg ?? options.input;
    if (!input) {
      console.error(chalk.red('Provide a capture bundle directory (or --input <path>)'));
      process.exit(1);
    }
    if (!fs.existsSync(input)) {
      console.error(chalk.red('Capture path not found:'), input);
      process.exit(1);
    }

    const isLegacy = options.legacyJsonl || fs.statSync(input).isFile();
    if (isLegacy) {
      await runLegacyReplay(input, options);
      return;
    }

    if (!MODES.includes(options.mode as ReplayComparisonMode)) {
      console.error(chalk.red(`Unsupported mode: ${options.mode}. Valid: ${MODES.join(', ')}`));
      process.exit(1);
    }

    const bundle = loadBundle(input);
    console.info(
      chalk.blue(`Replaying ${bundle.exchanges.length} exchange(s) against`),
      options.target
    );

    const queryReplacements = new Map<string, string>();
    for (const mapping of options.queryEnv) {
      const [name, envName] = mapping.split(':');
      if (!name || !envName) {
        console.error(chalk.red(`Invalid --query-env mapping: ${mapping} (expected NAME:ENV)`));
        process.exit(1);
      }
      const value = process.env[envName];
      if (value === undefined) {
        console.error(
          chalk.red(`--query-env ${mapping}: environment variable ${envName} is not set`)
        );
        process.exit(1);
      }
      queryReplacements.set(name, value);
    }

    const report = await replayCapture(bundle, {
      target: options.target,
      mode: options.mode as ReplayComparisonMode,
      delayMs: parseInt(options.delay, 10),
      ...(options.credentialEnv.length > 0
        ? { credentialProvider: credentialProviderFromEnvMappings(options.credentialEnv) }
        : {}),
      ...(queryReplacements.size > 0
        ? { queryValueProvider: (name: string): string | undefined => queryReplacements.get(name) }
        : {}),
      ...(options.ignorePointer.length > 0
        ? { normalization: { ignorePointers: options.ignorePointer } }
        : {}),
    });

    console.info();
    console.info(chalk.bold('Replay Report:'));
    console.info(chalk.gray(`  Total:   ${report.summary.total}`));
    console.info(chalk.green(`  Passed:  ${report.summary.passed}`));
    console.info(chalk.yellow(`  Failed:  ${report.summary.failed}`));
    console.info(chalk.red(`  Errors:  ${report.summary.errors}`));

    for (const result of report.results) {
      if (result.error) {
        console.info(
          chalk.red('✗'),
          `#${result.sequence} ${result.method} ${result.path} — ${result.error}`
        );
      } else if (!result.statusMatch) {
        console.info(
          chalk.yellow('⚠'),
          `#${result.sequence} ${result.method} ${result.path} — status ${result.originalStatus} → ${String(result.replayedStatus)}`
        );
      } else if (result.comparison && !result.comparison.match) {
        const diff =
          result.comparison.firstDiffPointer ??
          (result.comparison.firstDiffByteOffset !== undefined
            ? `first diff at byte ${result.comparison.firstDiffByteOffset}`
            : result.comparison.firstDiffEvent
              ? `event ${result.comparison.firstDiffEvent.index}: ${result.comparison.firstDiffEvent.reason}`
              : (result.comparison.detail ?? 'differs'));
        console.info(
          chalk.yellow('⚠'),
          `#${result.sequence} ${result.method} ${result.path} — ${diff}`
        );
      } else if (options.verbose) {
        console.info(
          chalk.green('✓'),
          `#${result.sequence} ${result.method} ${result.path} — ${String(result.replayedStatus)} (${result.durationMs}ms)`
        );
      }
    }

    if (options.report) {
      fs.writeFileSync(options.report, JSON.stringify(report, null, 2), { mode: 0o600 });
      fs.chmodSync(options.report, 0o600); // mode option only applies at creation
      console.info(chalk.gray(`Report written to ${options.report}`));
    }

    if (options.failOnDiff && (report.summary.failed > 0 || report.summary.errors > 0)) {
      process.exit(1);
    }
  });

async function runLegacyReplay(input: string, options: ReplayCliOptions): Promise<void> {
  const authManager = options.token ? AuthManager.fromToken(options.token) : new AuthManager();
  if (authManager.isAuthenticated()) {
    console.info(chalk.blue('Using auth token:'), authManager.redactedToken());
  }
  console.info(chalk.blue('Replaying legacy traffic against'), options.target);

  const report = await replayTraffic(input, options.target, authManager, {
    ...(options.onlyStatus !== undefined ? { onlyStatus: options.onlyStatus } : {}),
    delay: parseInt(options.delay, 10),
  });

  console.info();
  console.info(chalk.bold('Replay Report:'));
  console.info(chalk.gray(`  Total:     ${report.summary.total}`));
  console.info(chalk.green(`  Passed:    ${report.summary.passed}`));
  console.info(chalk.yellow(`  Failed:    ${report.summary.failed}`));
  console.info(chalk.red(`  Errors:    ${report.summary.errors}`));
  console.info(chalk.gray(`  Avg time:  ${report.summary.avgDurationMs}ms`));

  for (const result of report.results) {
    if (result.error) {
      console.info(chalk.red('✗'), `${result.method} ${result.path} — ERROR: ${result.error}`);
    } else if (!result.statusMatch) {
      console.info(
        chalk.yellow('⚠'),
        `${result.method} ${result.path} — status ${result.originalStatus} → ${result.replayedStatus}`
      );
    } else if (result.bodyDiff) {
      console.info(chalk.yellow('⚠'), `${result.method} ${result.path} — ${result.bodyDiff}`);
    } else if (options.verbose) {
      console.info(
        chalk.green('✓'),
        `${result.method} ${result.path} — ${result.replayedStatus} (${result.durationMs}ms)`
      );
    }
  }

  if (options.failOnDiff && (report.summary.failed > 0 || report.summary.errors > 0)) {
    process.exit(1);
  }
}

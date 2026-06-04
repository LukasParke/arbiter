import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { replayTraffic } from '../replay.js';
import { AuthManager } from '../auth.js';

export const replayCommand = new Command('replay')
  .description('Replay captured traffic for regression testing')
  .requiredOption('-i, --input <path>', 'path to traffic JSONL file')
  .requiredOption('--target <url>', 'target API URL to replay against')
  .option('--token <token>', 'authentication token for replayed requests')
  .option('--only-status', 'only compare status codes, skip body comparison')
  .option('--delay <ms>', 'delay between requests in milliseconds', '0')
  .option('--fail-on-diff', 'exit with code 1 if any regressions are found')
  .option('-v, --verbose', 'show details for all requests, not just failures')
  .action(
    async (options: {
      input: string;
      target: string;
      token?: string;
      onlyStatus?: boolean;
      delay: string;
      failOnDiff?: boolean;
      verbose?: boolean;
    }) => {
      if (!fs.existsSync(options.input)) {
        console.error(chalk.red('Traffic file not found:'), options.input);
        process.exit(1);
      }

      const authManager = options.token
        ? AuthManager.fromToken(options.token)
        : new AuthManager();

      if (authManager.isAuthenticated()) {
        console.info(chalk.blue('Using auth token:'), authManager.redactedToken());
      }

      console.info(chalk.blue('Replaying traffic against'), options.target);

      const report = await replayTraffic(options.input, options.target, authManager, {
        onlyStatus: options.onlyStatus,
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
          console.info(
            chalk.red('✗'),
            `${result.method} ${result.path} — ERROR: ${result.error}`
          );
        } else if (!result.statusMatch) {
          console.info(
            chalk.yellow('⚠'),
            `${result.method} ${result.path} — status ${result.originalStatus} → ${result.replayedStatus}`
          );
        } else if (result.bodyDiff) {
          console.info(
            chalk.yellow('⚠'),
            `${result.method} ${result.path} — ${result.bodyDiff}`
          );
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
  );

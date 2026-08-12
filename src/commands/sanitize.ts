import { Command } from 'commander';
import chalk from 'chalk';
import { sanitizeBundle } from '../bundle/sanitize.js';
import { RedactionPolicy } from '../capture/index.js';

interface SanitizeCliOptions {
  output: string;
  redactHeader: string[];
  allowQuery: string[];
  rejectSecretEnv: string[];
  allowBinaryMediaType: string[];
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export const sanitizeCommand = new Command('sanitize')
  .description(
    'Revalidate an untrusted capture bundle and emit a new deterministic sanitized bundle'
  )
  .argument('<bundle>', 'path to the input capture bundle directory')
  .requiredOption(
    '-o, --output <dir>',
    'directory for the sanitized bundle (must not exist or be empty)'
  )
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
    '--reject-secret-env <env-name>',
    'env var whose value must not appear anywhere (repeatable)',
    collect,
    []
  )
  .option(
    '--allow-binary-media-type <prefix>',
    'media type prefix allowed to remain unscanned binary (repeatable)',
    collect,
    []
  )
  .action((bundlePath: string, options: SanitizeCliOptions) => {
    const rejectSecrets: string[] = [];
    for (const envName of options.rejectSecretEnv) {
      const value = process.env[envName];
      if (value === undefined || value.length === 0) {
        console.error(chalk.red(`--reject-secret-env ${envName}: environment variable is not set`));
        process.exit(1);
      }
      rejectSecrets.push(value);
    }

    try {
      const result = sanitizeBundle(bundlePath, {
        output: options.output,
        redaction: new RedactionPolicy({
          redactHeaders: options.redactHeader,
          allowQuery: options.allowQuery,
        }),
        rejectSecrets,
        allowBinaryMediaTypes: options.allowBinaryMediaType,
      });
      console.info(
        chalk.green(
          `Sanitized ${result.bundle.exchanges.length} exchange(s) to ${options.output} (${result.redactedHeaderCount} redacted header entries)`
        )
      );
    } catch (err) {
      console.error(chalk.red('Sanitize failed:'), err instanceof Error ? err.message : err);
      process.exit(1);
    }
  });

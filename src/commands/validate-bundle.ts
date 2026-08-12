import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { loadBundle } from '../bundle/index.js';
import { BasicOpenAPIValidator, CommandValidator, validateCapture } from '../validation/index.js';

interface ValidateBundleCliOptions {
  spec?: string;
  command?: string;
  strict?: boolean;
  report?: string;
}

export const validateBundleCommand = new Command('validate')
  .description('Validate a capture bundle against a contract')
  .argument('<bundle>', 'path to the capture bundle directory')
  .option('-s, --spec <path>', 'OpenAPI spec for the basic validator')
  .option('--command <cmd>', 'external validator command (stdin JSON, stdout violations array)')
  .option('--strict', 'exit 1 on any violation')
  .option('--report <path>', 'write the JSON validation report to a file')
  .action(async (bundlePath: string, options: ValidateBundleCliOptions) => {
    if (!options.spec && !options.command) {
      console.error(chalk.red('Provide --spec <path> or --command <cmd>'));
      process.exit(1);
    }
    const bundle = loadBundle(bundlePath);
    const validator = options.command
      ? new CommandValidator(options.command)
      : new BasicOpenAPIValidator(options.spec as string);

    const report = await validateCapture(bundle, validator);

    console.info(chalk.bold('Validation Report:'));
    console.info(chalk.gray(`  Validator:  ${report.validator}`));
    console.info(chalk.gray(`  Exchanges:  ${report.exchangeCount}`));
    console.info(
      report.valid
        ? chalk.green(`  Violations: 0`)
        : chalk.yellow(`  Violations: ${report.violations.length}`)
    );
    for (const violation of report.violations) {
      console.info(
        chalk.yellow('⚠'),
        `#${violation.sequence} ${violation.method} ${violation.path} [${violation.type}]: ${violation.message}`
      );
    }

    if (options.report) {
      fs.writeFileSync(options.report, JSON.stringify(report, null, 2), { mode: 0o600 });
      fs.chmodSync(options.report, 0o600); // mode option only applies at creation
      console.info(chalk.gray(`Report written to ${options.report}`));
    }

    if (options.strict && !report.valid) {
      process.exit(1);
    }
  });

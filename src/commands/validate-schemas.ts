import { Command } from 'commander';
import chalk from 'chalk';
import { validateSchemaCoverage, writeSchemaValidationReport } from '../diff.js';

export const validateSchemasCommand = new Command('validate-schemas')
  .description('Validate schema coverage in an OpenAPI spec')
  .requiredOption('-s, --spec <path>', 'path to OpenAPI spec')
  .option('-o, --output <path>', 'path to write JSON validation report')
  .option('--exit-on-gap', 'exit with code 2 if gaps are found')
  .action((options: { spec: string; output?: string; exitOnGap?: boolean }) => {
    const result = validateSchemaCoverage(options.spec);

    console.info('\n' + chalk.bold('Schema Coverage Report:'));
    console.info(`  Total endpoints: ${result.summary.totalEndpoints}`);
    console.info(
      `  Missing response schemas: ${result.summary.missingResponseSchemas > 0 ? chalk.red(String(result.summary.missingResponseSchemas)) : chalk.green('0')}`
    );
    console.info(
      `  Missing request schemas: ${result.summary.missingRequestSchemas > 0 ? chalk.red(String(result.summary.missingRequestSchemas)) : chalk.green('0')}`
    );
    console.info(
      `  Bare response schemas: ${result.summary.bareResponseSchemas > 0 ? chalk.yellow(String(result.summary.bareResponseSchemas)) : chalk.green('0')}`
    );
    console.info(
      `  Missing parameter schemas: ${result.summary.missingParamSchemas > 0 ? chalk.red(String(result.summary.missingParamSchemas)) : chalk.green('0')}`
    );
    console.info(`  Total gaps: ${result.summary.totalGaps > 0 ? chalk.red(String(result.summary.totalGaps)) : chalk.green('0')}`);

    if (result.gaps.length > 0) {
      const byCategory = new Map<string, SchemaGap[]>();
      for (const gap of result.gaps) {
        const list = byCategory.get(gap.category) || [];
        list.push(gap);
        byCategory.set(gap.category, list);
      }

      for (const [category, gaps] of byCategory) {
        console.info('\n' + chalk.yellow(`${category}:`));
        for (const gap of gaps) {
          console.info(chalk.yellow(`  ${gap.method} ${gap.path} | ${gap.operationId}`));
          console.info(chalk.gray(`    → ${gap.detail}`));
        }
      }
    } else {
      console.info('\n' + chalk.green('✓ All endpoints have complete schema coverage!'));
    }

    if (options.output) {
      writeSchemaValidationReport(result, options.output);
      console.info('\n' + chalk.green(`Report written to ${options.output}`));
    }

    if (options.exitOnGap && result.gaps.length > 0) {
      process.exit(2);
    }
  });

interface SchemaGap {
  path: string;
  method: string;
  operationId: string;
  category: string;
  detail: string;
}

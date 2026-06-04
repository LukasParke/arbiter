import { Command } from 'commander';
import chalk from 'chalk';
import { diffFromTraffic, writeDiffReport } from '../diff.js';

export const diffCommand = new Command('diff')
  .description('Diff captured traffic against an existing OpenAPI spec')
  .requiredOption('-s, --spec <path>', 'path to existing OpenAPI spec')
  .requiredOption('-t, --traffic <path>', 'path to traffic JSONL file')
  .option('-o, --output <path>', 'path to write JSON diff report')
  .option('--exit-on-gap', 'exit with code 2 if gaps are found')
  .action((options: { spec: string; traffic: string; output?: string; exitOnGap?: boolean }) => {
    const result = diffFromTraffic(options.spec, options.traffic);
    console.info('\n' + chalk.bold('Diff Report:'));
    console.info(JSON.stringify(result.summary, null, 2));

    if (result.missingEndpoints.length > 0) {
      console.info('\n' + chalk.yellow('Missing endpoints:'));
      for (const ep of result.missingEndpoints) {
        console.info(chalk.yellow(`  ${ep.method} ${ep.path}`));
      }
    }

    if (result.queryParamGaps.length > 0) {
      console.info('\n' + chalk.yellow('Query param gaps:'));
      for (const gap of result.queryParamGaps) {
        console.info(
          chalk.yellow(`  ${gap.method} ${gap.path}: ${gap.missingQueryParams.join(', ')}`)
        );
      }
    }

    if (options.output) {
      writeDiffReport(result, options.output);
      console.info('\n' + chalk.green(`Report written to ${options.output}`));
    }

    if (options.exitOnGap && result.missingEndpoints.length > 0) {
      process.exit(2);
    }
  });

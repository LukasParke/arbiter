import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { inferFromTraffic, formatAsComponents } from '../infer.js';

export const inferSchemasCommand = new Command('infer-schemas')
  .description('Infer OpenAPI schemas from captured traffic')
  .requiredOption('-i, --input <path>', 'path to traffic JSONL file')
  .option('-o, --output <path>', 'path to write inferred schemas YAML file')
  .option('--json', 'output as JSON instead of YAML')
  .action(
    (options: { input: string; output?: string; json?: boolean }) => {
      if (!fs.existsSync(options.input)) {
        console.error(chalk.red('Traffic file not found:'), options.input);
        process.exit(1);
      }

      console.info(chalk.blue('Inferring schemas from'), options.input);
      const endpoints = inferFromTraffic(options.input);

      if (endpoints.length === 0) {
        console.warn(chalk.yellow('No JSON responses found in traffic file'));
        return;
      }

      console.info(chalk.green(`Inferred schemas for ${endpoints.length} endpoint(s):`));
      for (const ep of endpoints) {
        console.info(
          chalk.gray(
            `  ${ep.method} ${ep.path} (${ep.statusCode}) — ${ep.sampleCount} sample(s)`
          )
        );
      }

      if (options.json) {
        const output = {
          components: {
            schemas: Object.fromEntries(
              endpoints.map((ep) => {
                const name = `${ep.method.toLowerCase()}_${ep.path
                  .replace(/[^a-zA-Z0-9]/g, '_')
                  .replace(/_+/g, '_')
                  .replace(/^_+|_+$/g, '')}_${ep.statusCode}_response`;
                return [name, ep.schema];
              })
            ),
          },
        };
        const jsonOut = JSON.stringify(output, null, 2);
        if (options.output) {
          fs.writeFileSync(options.output, jsonOut);
          console.info(chalk.green('Wrote schemas to'), options.output);
        } else {
          console.info(jsonOut);
        }
      } else {
        const yamlOut = formatAsComponents(endpoints);
        if (options.output) {
          fs.writeFileSync(options.output, yamlOut + '\n');
          console.info(chalk.green('Wrote schemas to'), options.output);
        } else {
          console.info(yamlOut);
        }
      }
    }
  );

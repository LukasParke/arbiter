import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { generateSpecFromTraffic, specToYAML, specToJSON } from '../generate-spec.js';

export const generateSpecCommand = new Command('generate-spec')
  .description('Generate a complete OpenAPI spec from captured traffic')
  .requiredOption('-i, --input <path>', 'path to traffic JSONL file')
  .option('-o, --output <path>', 'path to write the generated spec')
  .option('--json', 'output as JSON instead of YAML')
  .option('--title <title>', 'API title in generated spec', 'Generated API Specification')
  .option('--version <version>', 'API version in generated spec', '1.0.0')
  .option('--server-url <url>', 'server URL for generated spec')
  .action(
    (options: {
      input: string;
      output?: string;
      json?: boolean;
      title: string;
      version: string;
      serverUrl?: string;
    }) => {
      if (!fs.existsSync(options.input)) {
        console.error(chalk.red('Traffic file not found:'), options.input);
        process.exit(1);
      }

      console.info(chalk.blue('Generating OpenAPI spec from'), options.input);

      const spec = generateSpecFromTraffic(options.input, {
        title: options.title,
        version: options.version,
        serverUrl: options.serverUrl,
      });

      const pathCount = Object.keys(spec.paths).length;
      const schemaCount = Object.keys(spec.components.schemas).length;

      console.info(chalk.green(`Generated spec with ${pathCount} path(s) and ${schemaCount} schema(s)`));

      const output = options.json ? specToJSON(spec) : specToYAML(spec);

      if (options.output) {
        fs.writeFileSync(options.output, output + '\n');
        console.info(chalk.green('Wrote spec to'), options.output);
      } else {
        console.info(output);
      }
    }
  );

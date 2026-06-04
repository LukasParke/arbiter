import { Command } from 'commander';
import chalk from 'chalk';
import { startServers } from '../server.js';
import { diffAgainstSpec } from '../diff.js';

export const startCommand = new Command('start')
  .description('Start the proxy and documentation servers')
  .requiredOption('-t, --target <url>', 'target API URL to proxy to')
  .option('-p, --port <number>', 'port to run the proxy server on', '8080')
  .option('-d, --docs-port <number>', 'port to run the documentation server on', '9000')
  .option('--db-path <path>', 'path to SQLite database file for persistence')
  .option('--docs-only', 'run only the documentation server')
  .option('--proxy-only', 'run only the proxy server')
  .option('--diff-against <path>', 'path to an existing OpenAPI spec to diff against')
  .option('--exit-on-gap', 'exit with code 2 if captured endpoints are missing from the spec')
  .option('-v, --verbose', 'enable verbose logging')
  .action(
    async (options: {
      target: string;
      port: string;
      docsPort: string;
      verbose?: boolean;
      dbPath?: string;
      diffAgainst?: string;
      exitOnGap?: boolean;
    }) => {
      console.info('Starting Arbiter...');
      const { proxyServer, docsServer } = await startServers({
        target: options.target,
        proxyPort: parseInt(options.port, 10),
        docsPort: parseInt(options.docsPort, 10),
        verbose: options.verbose,
        dbPath: options.dbPath,
        diffAgainst: options.diffAgainst,
      });

      // Handle graceful shutdown with diff check
      const shutdown = (signal: string): void => {
        console.info(`\nReceived ${signal}, shutting down...`);
        proxyServer.close();
        docsServer.close();

        if (options.diffAgainst) {
          try {
            const result = diffAgainstSpec(options.diffAgainst);
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
            if (options.exitOnGap && result.missingEndpoints.length > 0) {
              process.exit(2);
            }
          } catch (e) {
            console.error(chalk.red('Diff failed:'), e);
            process.exit(1);
          }
        }

        process.exit(0);
      };

      process.on('SIGTERM', () => shutdown('SIGTERM'));
      process.on('SIGINT', () => shutdown('SIGINT'));
    }
  );

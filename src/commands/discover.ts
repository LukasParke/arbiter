import { Command } from 'commander';
import chalk from 'chalk';
import { spawnSync } from 'child_process';
import fs from 'fs';

export const discoverCommand = new Command('discover')
  .description('Run full discovery pipeline: start proxy, generate traffic, diff against spec')
  .requiredOption('-s, --spec <path>', 'path to existing OpenAPI spec to diff against')
  .requiredOption('-t, --target <url>', 'target API URL to proxy to')
  .option('--compose-file <path>', 'docker-compose file for infrastructure', 'docker-compose.yml')
  .option('--traffic-output <path>', 'path to write traffic JSONL', '/tmp/traffic.jsonl')
  .option('--report-output <path>', 'path to write diff report', '/tmp/diff_report.json')
  .option('--token <token>', 'X-Plex-Token for authenticated requests')
  .option('--exit-on-gap', 'exit with code 2 if gaps are found')
  .action(
    async (options: {
      spec: string;
      target: string;
      composeFile: string;
      trafficOutput: string;
      reportOutput: string;
      token?: string;
      exitOnGap?: boolean;
    }) => {
      // 1. Start docker compose if compose-file exists
      if (fs.existsSync(options.composeFile)) {
        console.info(chalk.blue('Starting docker compose...'));
        const up = spawnSync('docker', ['compose', '-f', options.composeFile, 'up', '-d'], {
          stdio: 'inherit',
        });
        if (up.status !== 0) {
          console.error(chalk.red('Failed to start docker compose'));
          process.exit(1);
        }

        // Wait for services to be healthy
        console.info(chalk.blue('Waiting for services...'));
        await new Promise((resolve) => setTimeout(resolve, 15000));
      }

      // 2. Generate traffic against the target (assumes proxy is running if needed)
      console.info(chalk.blue('Generating traffic...'));
      const trafficArgs = [
        'generate-traffic',
        '--target',
        options.target,
        '--output',
        options.trafficOutput,
      ];
      if (options.token) {
        trafficArgs.push('--token', options.token);
      }
      const traffic = spawnSync(process.argv[0], [process.argv[1], ...trafficArgs], {
        encoding: 'utf-8',
        stdio: ['inherit', 'pipe', 'inherit'],
      });
      if (traffic.stdout) {
        console.info(traffic.stdout);
      }

      // 3. Diff
      console.info(chalk.blue('Running diff...'));
      const diffArgs = ['diff', '--spec', options.spec, '--traffic', options.trafficOutput];
      if (options.reportOutput) {
        diffArgs.push('--output', options.reportOutput);
      }
      if (options.exitOnGap) {
        diffArgs.push('--exit-on-gap');
      }
      const diff = spawnSync(process.argv[0], [process.argv[1], ...diffArgs], {
        encoding: 'utf-8',
        stdio: 'inherit',
      });

      // 4. Stop docker compose
      if (fs.existsSync(options.composeFile)) {
        console.info(chalk.blue('Stopping docker compose...'));
        spawnSync('docker', ['compose', '-f', options.composeFile, 'down'], {
          stdio: 'inherit',
        });
      }

      process.exit(diff.status ?? 0);
    }
  );

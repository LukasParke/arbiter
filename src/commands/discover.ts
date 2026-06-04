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
  .action(async (options) => {
    // 1. Start docker compose if compose-file exists
    if (fs.existsSync(options.composeFile)) {
      console.log(chalk.blue('Starting docker compose...'));
      const up = spawnSync('docker', ['compose', '-f', options.composeFile, 'up', '-d'], { stdio: 'inherit' });
      if (up.status !== 0) {
        console.error(chalk.red('Failed to start docker compose'));
        process.exit(1);
      }

      // Wait for services to be healthy
      console.log(chalk.blue('Waiting for services...'));
      await new Promise((resolve) => setTimeout(resolve, 15000));
    }

    // 2. Start arbiter proxy in background (we'll use the existing server module)
    // For simplicity, this command assumes the proxy is already running or will be started separately
    console.log(chalk.yellow('Note: This command assumes the Arbiter proxy is running.'));
    console.log(chalk.yellow('Start it in another terminal with: arbiter start -t <target>'));

    // 3. Generate traffic
    console.log(chalk.blue('Generating traffic...'));
    // We'll shell out to ourselves for generate-traffic
    const trafficArgs = ['generate-traffic', '--target', 'http://localhost:8080'];
    if (options.token) {
      trafficArgs.push('--token', options.token);
    }
    const traffic = spawnSync(process.argv[0], [process.argv[1], ...trafficArgs], {
      encoding: 'utf-8',
      stdio: ['inherit', 'pipe', 'inherit'],
    });
    console.log(traffic.stdout);

    // 4. Diff
    console.log(chalk.blue('Running diff...'));
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

    // 5. Stop docker compose
    if (fs.existsSync(options.composeFile)) {
      console.log(chalk.blue('Stopping docker compose...'));
      spawnSync('docker', ['compose', '-f', options.composeFile, 'down'], { stdio: 'inherit' });
    }

    process.exit(diff.status || 0);
  });

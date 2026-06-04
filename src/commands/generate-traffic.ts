import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import { AuthManager } from '../auth.js';

interface TrafficEntry {
  path: string;
  method: string;
  queryParams: string[];
  status: number;
  body?: string;
  contentType?: string;
}

export const generateTrafficCommand = new Command('generate-traffic')
  .description('Generate synthetic traffic against a target API')
  .requiredOption('--target <url>', 'base URL of the target API')
  .option('--token <token>', 'X-Plex-Token for authenticated requests')
  .option('--delay <ms>', 'delay between requests in ms', '100')
  .option('-o, --output <path>', 'path to write traffic JSONL file')
  .option('--capture-bodies', 'capture response bodies in traffic output')
  .option('--max-body-size <bytes>', 'maximum body size to capture', '50000')
  .action(
    async (options: {
      target: string;
      token?: string;
      delay: string;
      output?: string;
      captureBodies?: boolean;
      maxBodySize: string;
    }) => {
      const baseUrl = options.target.replace(/\/$/, '');
      const delay = parseInt(options.delay, 10);
      const outputPath = options.output;
      const captureBodies = options.captureBodies || false;
      const maxBodySize = parseInt(options.maxBodySize, 10);
      const traffic: TrafficEntry[] = [];

      // Resolve auth: CLI token takes precedence over saved config
      const authManager = options.token
        ? AuthManager.fromToken(options.token)
        : new AuthManager();
      if (authManager.isAuthenticated()) {
        console.info(chalk.blue('Using auth token:'), authManager.redactedToken());
      }

      const endpoints = [
        { method: 'GET', path: '/' },
        { method: 'GET', path: '/identity' },
        { method: 'GET', path: '/library' },
        { method: 'GET', path: '/library/sections' },
        { method: 'GET', path: '/library/sections/1/all' },
        { method: 'GET', path: '/library/sections/1/onDeck' },
        { method: 'GET', path: '/library/sections/1/recentlyAdded' },
        { method: 'GET', path: '/library/metadata/1' },
        { method: 'GET', path: '/library/metadata/1/children' },
        { method: 'GET', path: '/status/sessions' },
        { method: 'GET', path: '/status/sessions/history/all' },
        { method: 'GET', path: '/accounts' },
        { method: 'GET', path: '/devices' },
        { method: 'GET', path: '/clients' },
        { method: 'GET', path: '/servers' },
        { method: 'GET', path: '/hubs/search' },
        { method: 'GET', path: '/playlists' },
        { method: 'GET', path: '/butler' },
        { method: 'GET', path: '/activities' },
        { method: 'GET', path: '/updater/status' },
        { method: 'GET', path: '/system/agents' },
        { method: 'GET', path: '/system/settings' },
        { method: 'GET', path: '/system/updates' },
        { method: 'GET', path: '/statistics/bandwidth' },
        { method: 'GET', path: '/statistics/resources' },
        { method: 'GET', path: '/diagnostics' },
        { method: 'GET', path: '/sync' },
        { method: 'GET', path: '/sync/items' },
        { method: 'GET', path: '/sync/queue' },
        { method: 'GET', path: '/services/browse' },
        { method: 'GET', path: '/media/grabbers' },
        { method: 'GET', path: '/livetv/dvrs' },
        { method: 'GET', path: '/livetv/epg' },
        { method: 'GET', path: '/channels' },
        { method: 'GET', path: '/player/timeline/poll' },
        { method: 'GET', path: '/player/playback/playMedia' },
        { method: 'GET', path: '/transcode/sessions' },
        { method: 'GET', path: '/security/resources' },
        { method: 'GET', path: '/security/token' },
        { method: 'GET', path: '/downloadQueue' },
      ];

      let passed = 0;
      let failed = 0;
      let skipped = 0;

      for (const endpoint of endpoints) {
        const url = new URL(endpoint.path, baseUrl);
        // Add auth query params
        const authParams = authManager.getQueryParams();
        for (const [key, value] of Object.entries(authParams)) {
          url.searchParams.set(key, value);
        }

        let status = 0;
        let body: string | undefined;
        let contentType: string | undefined;

        try {
          const response = await fetch(url.toString(), {
            method: endpoint.method,
            headers: authManager.getHeaders(),
          });
          status = response.status;
          contentType = response.headers.get('content-type') || undefined;

          if (captureBodies && response.ok) {
            const text = await response.text();
            body = text.length > maxBodySize ? text.slice(0, maxBodySize) + '...[truncated]' : text;
          }

          if (response.ok) {
            console.info(chalk.green('✓'), `${endpoint.method} ${endpoint.path}`);
            passed++;
          } else if (response.status === 401) {
            console.info(chalk.yellow('○'), `${endpoint.method} ${endpoint.path} (unauthorized)`);
            skipped++;
          } else {
            console.info(chalk.red('✗'), `${endpoint.method} ${endpoint.path} (${response.status})`);
            failed++;
          }
        } catch (err) {
          status = 0;
          console.info(
            chalk.red('✗'),
            `${endpoint.method} ${endpoint.path} (error: ${(err as Error).message})`
          );
          failed++;
        }

        const entry: TrafficEntry = {
          path: url.toString(),
          method: endpoint.method,
          queryParams: Array.from(url.searchParams.keys()),
          status,
        };
        if (captureBodies) {
          entry.body = body;
          entry.contentType = contentType;
        }
        traffic.push(entry);

        if (delay > 0) {
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }

      if (outputPath) {
        const lines = traffic.map((entry) => JSON.stringify(entry)).join('\n');
        fs.writeFileSync(outputPath, lines + '\n');
        console.info(chalk.green(`Traffic written to ${outputPath}`));
      }

      console.info('\n' + chalk.bold('Traffic Generation Complete:'));
      console.info(`  ${chalk.green('Passed:')} ${passed}`);
      console.info(`  ${chalk.yellow('Skipped:')} ${skipped}`);
      console.info(`  ${chalk.red('Failed:')} ${failed}`);
    }
  );

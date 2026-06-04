import { Command } from 'commander';
import chalk from 'chalk';

export const generateTrafficCommand = new Command('generate-traffic')
  .description('Generate synthetic traffic against a target API')
  .requiredOption('--target <url>', 'base URL of the target API')
  .option('--token <token>', 'X-Plex-Token for authenticated requests')
  .option('--delay <ms>', 'delay between requests in ms', '100')
  .action(async (options) => {
    const baseUrl = options.target.replace(/\/$/, '');
    const token = options.token;
    const delay = parseInt(options.delay, 10);

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
      if (token) {
        url.searchParams.set('X-Plex-Token', token);
      }

      try {
        const response = await fetch(url.toString(), { method: endpoint.method });
        if (response.ok) {
          console.log(chalk.green('✓'), `${endpoint.method} ${endpoint.path}`);
          passed++;
        } else if (response.status === 401) {
          console.log(chalk.yellow('○'), `${endpoint.method} ${endpoint.path} (unauthorized)`);
          skipped++;
        } else {
          console.log(chalk.red('✗'), `${endpoint.method} ${endpoint.path} (${response.status})`);
          failed++;
        }
      } catch (err) {
        console.log(chalk.red('✗'), `${endpoint.method} ${endpoint.path} (error: ${(err as Error).message})`);
        failed++;
      }

      if (delay > 0) {
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    console.log('\n' + chalk.bold('Traffic Generation Complete:'));
    console.log(`  ${chalk.green('Passed:')} ${passed}`);
    console.log(`  ${chalk.yellow('Skipped:')} ${skipped}`);
    console.log(`  ${chalk.red('Failed:')} ${failed}`);
  });

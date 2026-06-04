import { Command } from 'commander';
import chalk from 'chalk';
import { AuthManager } from '../auth.js';

export const authCommand = new Command('auth')
  .description('Manage authentication tokens for API requests')
  .addCommand(
    new Command('set')
      .description('Save an authentication token')
      .requiredOption('--token <token>', 'the authentication token')
      .option('--type <type>', 'auth type: plex-token, bearer, api-key', 'plex-token')
      .option('--header <name>', 'header name for api-key auth')
      .action((options: { token: string; type: string; header?: string }) => {
        const config = {
          type: options.type as 'plex-token' | 'bearer' | 'api-key',
          token: options.token,
          headerName: options.header,
        };
        const manager = new AuthManager(config);
        manager.saveToDisk();
        console.info(chalk.green('Authentication token saved'));
        console.info(chalk.gray(`  Type: ${config.type}`));
        console.info(chalk.gray(`  Token: ${manager.redactedToken()}`));
      })
  )
  .addCommand(
    new Command('clear')
      .description('Remove saved authentication token')
      .action(() => {
        const manager = new AuthManager({ type: 'plex-token', token: '' });
        manager.saveToDisk();
        console.info(chalk.green('Authentication token cleared'));
      })
  )
  .addCommand(
    new Command('show')
      .description('Show current authentication status')
      .action(() => {
        const manager = new AuthManager();
        if (manager.isAuthenticated()) {
          console.info(chalk.green('Authenticated'));
          console.info(chalk.gray(`  Token: ${manager.redactedToken()}`));
        } else {
          console.info(chalk.yellow('No authentication token configured'));
          console.info(chalk.gray('Run: arbiter auth set --token <your-token>'));
        }
      })
  );

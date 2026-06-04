#!/usr/bin/env node
import { Command } from 'commander';
import { startCommand } from './commands/start.js';
import { diffCommand } from './commands/diff.js';
import { generateTrafficCommand } from './commands/generate-traffic.js';
import { discoverCommand } from './commands/discover.js';

const program = new Command();

program
  .name('arbiter')
  .description('API proxy with OpenAPI generation and HAR export capabilities')
  .version('1.0.0');

// Register subcommands
program.addCommand(startCommand, { isDefault: true });
program.addCommand(diffCommand);
program.addCommand(generateTrafficCommand);
program.addCommand(discoverCommand);

program.parse(process.argv);

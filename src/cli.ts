#!/usr/bin/env node
import { Command } from 'commander';
import { startCommand } from './commands/start.js';
import { diffCommand } from './commands/diff.js';
import { generateTrafficCommand } from './commands/generate-traffic.js';
import { discoverCommand } from './commands/discover.js';
import { validateSchemasCommand } from './commands/validate-schemas.js';
import { authCommand } from './commands/auth.js';
import { inferSchemasCommand } from './commands/infer-schemas.js';
import { replayCommand } from './commands/replay.js';

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
program.addCommand(validateSchemasCommand);
program.addCommand(authCommand);
program.addCommand(inferSchemasCommand);
program.addCommand(replayCommand);

program.parse(process.argv);

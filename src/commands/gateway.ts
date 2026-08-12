import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import {
  startGateway,
  credentialProviderFromCommand,
  type GatewayPolicy,
} from '../gateway/index.js';

interface GatewayCliOptions {
  policy: string;
  credentialCommand: string;
  credentialHeader: string;
  credentialPrefix?: string;
  port: string;
  host: string;
  readyFile?: string;
}

export const gatewayCommand = new Command('gateway')
  .description('Run a credential-injecting gateway for untrusted clients')
  .requiredOption('--policy <path>', 'path to the gateway policy JSON file')
  .requiredOption(
    '--credential-command <cmd>',
    'command whose stdout supplies the upstream credential (never logged)'
  )
  .option('--credential-header <name>', 'header to carry the credential upstream', 'authorization')
  .option('--credential-prefix <prefix>', 'prefix for the credential value, e.g. Bearer')
  .option('-p, --port <number>', 'port to listen on (0 = random)', '0')
  .option('--host <hostname>', 'hostname to bind', '127.0.0.1')
  .option('--ready-file <path>', 'write listener metadata JSON atomically once ready')
  .action(async (options: GatewayCliOptions) => {
    let policy: GatewayPolicy;
    try {
      policy = JSON.parse(fs.readFileSync(options.policy, 'utf-8')) as GatewayPolicy;
    } catch (err) {
      console.error(chalk.red('Failed to read policy:'), err instanceof Error ? err.message : err);
      process.exit(1);
    }

    const gateway = await startGateway({
      policy,
      credentialProvider: credentialProviderFromCommand(
        options.credentialCommand,
        options.credentialHeader,
        options.credentialPrefix !== undefined ? { prefix: options.credentialPrefix } : {}
      ),
      listen: { hostname: options.host, port: parseInt(options.port, 10) },
      onRequest: (event) => {
        const mark = event.allowed ? chalk.green('✓') : chalk.red('✗');
        console.info(
          mark,
          `${event.method} ${event.path}`,
          event.allowed ? String(event.status) : chalk.red(event.denyReason ?? 'denied')
        );
      },
    });

    console.info(chalk.green('Arbiter gateway listening'));
    console.info(chalk.cyan(`  Gateway: ${gateway.url.toString()}`));
    console.info(chalk.gray(`  Target:  ${policy.targetOrigin}`));
    console.info(chalk.gray(`  Expires: ${policy.expiresAt}`));

    if (options.readyFile) {
      const tmp = `${options.readyFile}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          url: gateway.url.toString(),
          target: policy.targetOrigin,
          pid: process.pid,
        }),
        { mode: 0o600 }
      );
      fs.renameSync(tmp, options.readyFile);
    }

    const shutdown = (): void => {
      void gateway.close().then(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

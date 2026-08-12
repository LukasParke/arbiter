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
  captureOutput?: string;
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
  .option(
    '--capture-output <dir>',
    'record allowed gateway traffic and export an exact capture bundle on shutdown'
  )
  .action(async (options: GatewayCliOptions) => {
    let policy: GatewayPolicy;
    try {
      policy = JSON.parse(fs.readFileSync(options.policy, 'utf-8')) as GatewayPolicy;
    } catch (err) {
      console.error(chalk.red('Failed to read policy:'), err instanceof Error ? err.message : err);
      process.exit(1);
    }

    const port = Number(options.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      console.error(chalk.red(`--port must be an integer 0-65535 (got ${options.port})`));
      process.exit(1);
    }

    let gateway: Awaited<ReturnType<typeof startGateway>>;
    try {
      gateway = await startGatewayWith(policy, port, options);
    } catch (err) {
      console.error(
        chalk.red('Failed to start gateway:'),
        err instanceof Error ? err.message : err
      );
      process.exit(1);
    }
    function startGatewayWith(
      gatewayPolicy: GatewayPolicy,
      listenPort: number,
      cli: GatewayCliOptions
    ): ReturnType<typeof startGateway> {
      return startGateway({
        policy: gatewayPolicy,
        credentialProvider: credentialProviderFromCommand(
          cli.credentialCommand,
          cli.credentialHeader,
          cli.credentialPrefix !== undefined ? { prefix: cli.credentialPrefix } : {}
        ),
        listen: { hostname: cli.host, port: listenPort },
        ...(cli.captureOutput ? { capture: {} } : {}),
        onRequest: (event) => {
          const mark = event.allowed ? chalk.green('✓') : chalk.red('✗');
          console.info(
            mark,
            `${event.method} ${event.path}`,
            event.allowed ? String(event.status) : chalk.red(event.denyReason ?? 'denied')
          );
        },
      });
    }

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

    let shuttingDown = false;
    const shutdown = (): void => {
      if (shuttingDown) {
        return;
      }
      shuttingDown = true;
      void (async (): Promise<void> => {
        let exitCode = 0;
        try {
          if (options.captureOutput && gateway.capture) {
            await gateway.capture.waitForIdle();
            const { manifest } = await gateway.capture.export({ output: options.captureOutput });
            console.info(
              chalk.green(
                `Exported ${manifest.exchangeCount} exchange(s) to ${options.captureOutput}`
              )
            );
          }
        } catch (err) {
          console.error(
            chalk.red('Capture export failed:'),
            err instanceof Error ? err.message : err
          );
          exitCode = 1;
        } finally {
          await gateway.close();
          process.exit(exitCode);
        }
      })();
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

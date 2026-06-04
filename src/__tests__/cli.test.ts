import { describe, it, expect } from 'vitest';
import { Command } from 'commander';
import { startCommand } from '../commands/start.js';
import { diffCommand } from '../commands/diff.js';
import { generateTrafficCommand } from '../commands/generate-traffic.js';
import { discoverCommand } from '../commands/discover.js';

describe('CLI Options', () => {
  it('should require target URL', () => {
    const program = new Command();
    program
      .name('arbiter')
      .description('API proxy with OpenAPI generation and HAR export capabilities')
      .version('1.0.0')
      .requiredOption('-t, --target <url>', 'target API URL to proxy to')
      .option('-p, --port <number>', 'port to run the proxy server on', '8080')
      .option('-d, --docs-port <number>', 'port to run the documentation server on', '9000')
      .option('-k, --key <string>', 'API key to add to proxied requests')
      .option('--docs-only', 'run only the documentation server')
      .option('--proxy-only', 'run only the proxy server')
      .option('-v, --verbose', 'enable verbose logging');

    // Test without target URL
    expect(() => program.parse(['node', 'arbiter'])).toThrow();

    // Test with target URL
    const options = program.parse(['node', 'arbiter', '-t', 'http://example.com']).opts();
    expect(options.target).toBe('http://example.com');
    expect(options.port).toBe('8080');
    expect(options.docsPort).toBe('9000');
  });

  it('should handle custom ports', () => {
    const program = new Command();
    program
      .name('arbiter')
      .description('API proxy with OpenAPI generation and HAR export capabilities')
      .version('1.0.0')
      .requiredOption('-t, --target <url>', 'target API URL to proxy to')
      .option('-p, --port <number>', 'port to run the proxy server on', '8080')
      .option('-d, --docs-port <number>', 'port to run the documentation server on', '9000');

    const options = program
      .parse(['node', 'arbiter', '-t', 'http://example.com', '-p', '8081', '-d', '9001'])
      .opts();

    expect(options.port).toBe('8081');
    expect(options.docsPort).toBe('9001');
  });

  it('should handle API key', () => {
    const program = new Command();
    program
      .name('arbiter')
      .description('API proxy with OpenAPI generation and HAR export capabilities')
      .version('1.0.0')
      .requiredOption('-t, --target <url>', 'target API URL to proxy to')
      .option('-k, --key <string>', 'API key to add to proxied requests');

    const options = program
      .parse(['node', 'arbiter', '-t', 'http://example.com', '-k', 'test-api-key'])
      .opts();

    expect(options.key).toBe('test-api-key');
  });

  it('should handle server mode options', () => {
    const program = new Command();
    program
      .name('arbiter')
      .description('API proxy with OpenAPI generation and HAR export capabilities')
      .version('1.0.0')
      .requiredOption('-t, --target <url>', 'target API URL to proxy to')
      .option('--docs-only', 'run only the documentation server')
      .option('--proxy-only', 'run only the proxy server');

    // Test docs-only mode
    const docsOptions = program
      .parse(['node', 'arbiter', '-t', 'http://example.com', '--docs-only'])
      .opts();
    expect(docsOptions.docsOnly).toBe(true);

    // Test proxy-only mode
    const proxyOptions = program
      .parse(['node', 'arbiter', '-t', 'http://example.com', '--proxy-only'])
      .opts();
    expect(proxyOptions.proxyOnly).toBe(true);
  });

  it('should export start command with correct name and options', () => {
    expect(startCommand.name()).toBe('start');
    expect(startCommand.description()).toBe('Start the proxy and documentation servers');
    const options = startCommand.options.map((o) => o.long);
    expect(options).toContain('--target');
    expect(options).toContain('--port');
    expect(options).toContain('--docs-port');
    expect(options).toContain('--diff-against');
  });

  it('should export diff command with correct name and options', () => {
    expect(diffCommand.name()).toBe('diff');
    expect(diffCommand.description()).toBe('Diff captured traffic against an existing OpenAPI spec');
    const options = diffCommand.options.map((o) => o.long);
    expect(options).toContain('--spec');
    expect(options).toContain('--traffic');
    expect(options).toContain('--output');
  });

  it('should export generate-traffic command with correct name and options', () => {
    expect(generateTrafficCommand.name()).toBe('generate-traffic');
    expect(generateTrafficCommand.description()).toBe('Generate synthetic traffic against a target API');
    const options = generateTrafficCommand.options.map((o) => o.long);
    expect(options).toContain('--target');
    expect(options).toContain('--token');
    expect(options).toContain('--delay');
  });

  it('should export discover command with correct name and options', () => {
    expect(discoverCommand.name()).toBe('discover');
    expect(discoverCommand.description()).toBe(
      'Run full discovery pipeline: start proxy, generate traffic, diff against spec'
    );
    const options = discoverCommand.options.map((o) => o.long);
    expect(options).toContain('--spec');
    expect(options).toContain('--target');
    expect(options).toContain('--compose-file');
  });
});

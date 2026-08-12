import { describe, it, expect, afterEach } from 'vitest';
import net from 'net';
import { startServers } from '../../src/server.js';

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    cleanups.pop()?.();
  }
});

async function portOpen(port: number): Promise<boolean> {
  return await new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

describe('startServers modes', () => {
  it('proxy-only binds only the proxy listener', async () => {
    const { proxyServer, docsServer } = await startServers({
      target: 'http://127.0.0.1:59999',
      proxyPort: 4801,
      docsPort: 4802,
      proxyOnly: true,
    });
    cleanups.push(() => {
      proxyServer?.close();
      docsServer?.close();
    });
    expect(proxyServer).not.toBeNull();
    expect(docsServer).toBeNull();
    expect(await portOpen(4801)).toBe(true);
    expect(await portOpen(4802)).toBe(false);
  });

  it('docs-only binds only the docs listener', async () => {
    const { proxyServer, docsServer } = await startServers({
      target: 'http://127.0.0.1:59999',
      proxyPort: 4803,
      docsPort: 4804,
      docsOnly: true,
    });
    cleanups.push(() => {
      proxyServer?.close();
      docsServer?.close();
    });
    expect(proxyServer).toBeNull();
    expect(docsServer).not.toBeNull();
    expect(await portOpen(4803)).toBe(false);
    expect(await portOpen(4804)).toBe(true);
  });

  it('rejects proxy-only combined with docs-only', async () => {
    await expect(
      startServers({
        target: 'http://127.0.0.1:59999',
        proxyPort: 4805,
        docsPort: 4806,
        proxyOnly: true,
        docsOnly: true,
      })
    ).rejects.toThrow(/mutually exclusive/);
  });
});

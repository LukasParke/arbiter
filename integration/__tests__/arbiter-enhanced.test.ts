import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { startServers } from '../../src/server.js';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Arbiter Enhanced Features', () => {
  const targetPort = 5001;
  const proxyPort = 5002;
  const docsPort = 5003;

  let targetServer: any;
  let proxyServer: any;
  let docsServer: any;

  const targetApi = new Hono();

  // Endpoints that test path normalization
  targetApi.get('/items/123', (c) => c.json({ id: 123, type: 'numeric' }));
  targetApi.get('/items/550e8400-e29b-41d4-a716-446655440000', (c) =>
    c.json({ id: 'uuid', type: 'guid' })
  );
  targetApi.get('/items/com.plexapp.agents.imdb://tt0137523', (c) =>
    c.json({ id: 'plex-guid', type: 'guid' })
  );
  targetApi.get('/items/some-very-long-string-key-that-is-over-thirty-chars', (c) =>
    c.json({ id: 'key', type: 'string' })
  );

  // Endpoint with query params
  targetApi.get('/search', (c) => {
    const q = c.req.query('q');
    const limit = c.req.query('limit');
    return c.json({ q, limit: limit ? parseInt(limit) : 10 });
  });

  beforeAll(async () => {
    targetServer = serve({
      fetch: targetApi.fetch,
      port: targetPort,
    });

    // Write a minimal spec for diff testing
    const specPath = path.join(__dirname, 'test-spec.json');
    fs.writeFileSync(
      specPath,
      JSON.stringify(
        {
          openapi: '3.1.0',
          info: { title: 'Test', version: '1.0.0' },
          paths: {
            '/items/{id}': {
              get: {
                parameters: [
                  { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
                ],
                responses: { '200': { description: 'OK' } },
              },
            },
            '/search': {
              get: {
                parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }],
                responses: { '200': { description: 'OK' } },
              },
            },
          },
        },
        null,
        2
      )
    );

    const { proxyServer: proxy, docsServer: docs } = await startServers({
      target: `http://localhost:${targetPort}`,
      proxyPort: proxyPort,
      docsPort: docsPort,
      verbose: false,
      diffAgainst: specPath,
    });

    proxyServer = proxy;
    docsServer = docs;
  });

  afterAll(() => {
    targetServer?.close();
    proxyServer?.close();
    docsServer?.close();
    const specPath = path.join(__dirname, 'test-spec.json');
    try {
      fs.unlinkSync(specPath);
    } catch {}
  });

  it('should export traffic as JSONL', async () => {
    await fetch(`http://localhost:${proxyPort}/items/123`);
    await fetch(`http://localhost:${proxyPort}/items/456`);

    const response = await fetch(`http://localhost:${docsPort}/traffic.jsonl`);
    expect(response.status).toBe(200);

    const body = await response.text();
    const lines = body.trim().split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(2);

    for (const line of lines) {
      const entry = JSON.parse(line);
      expect(entry).toHaveProperty('timestamp');
      expect(entry).toHaveProperty('method');
      expect(entry).toHaveProperty('path');
      expect(entry).toHaveProperty('response_status');
    }
  });

  it('should normalize numeric IDs to {id}', async () => {
    await fetch(`http://localhost:${proxyPort}/items/123`);
    await fetch(`http://localhost:${proxyPort}/items/456`);

    const specResponse = await fetch(`http://localhost:${docsPort}/openapi.json`);
    const spec = (await specResponse.json()) as Record<string, any>;

    expect(spec.paths?.['/items/{id}']).toBeDefined();
    expect(spec.paths?.['/items/123']).toBeUndefined();
  });

  it('should normalize UUIDs to {guid}', async () => {
    await fetch(`http://localhost:${proxyPort}/items/550e8400-e29b-41d4-a716-446655440000`);

    const specResponse = await fetch(`http://localhost:${docsPort}/openapi.json`);
    const spec = (await specResponse.json()) as Record<string, any>;

    expect(spec.paths?.['/items/{guid}']).toBeDefined();
  });

  it('should normalize long string keys to {key}', async () => {
    await fetch(
      `http://localhost:${proxyPort}/items/some-very-long-string-key-that-is-over-thirty-chars`
    );

    const specResponse = await fetch(`http://localhost:${docsPort}/openapi.json`);
    const spec = (await specResponse.json()) as Record<string, any>;

    expect(spec.paths?.['/items/{key}']).toBeDefined();
  });

  it('should produce a diff report', async () => {
    await fetch(`http://localhost:${proxyPort}/search?q=test&limit=10`);

    const response = await fetch(`http://localhost:${docsPort}/diff`);
    expect(response.status).toBe(200);

    const diff = (await response.json()) as Record<string, any>;
    expect(diff).toHaveProperty('summary');
    expect(diff).toHaveProperty('missingEndpoints');
    expect(diff).toHaveProperty('untestedEndpoints');
    expect(diff).toHaveProperty('queryParamGaps');

    // The /items/{guid} and /items/{key} paths should be missing from the spec
    const missingPaths = diff.missingEndpoints.map((e: any) => e.path);
    expect(missingPaths).toContain('/items/{guid}');
    expect(missingPaths).toContain('/items/{key}');

    // The 'limit' query param on /search should be a gap
    const searchGap = diff.queryParamGaps.find((g: any) => g.path === '/search');
    expect(searchGap).toBeDefined();
    expect(searchGap.missingQueryParams).toContain('limit');
  });

  it('should expose WS log endpoint', async () => {
    const response = await fetch(`http://localhost:${docsPort}/ws`);
    expect(response.status).toBe(200);

    const data = (await response.json()) as Record<string, any>;
    expect(data).toHaveProperty('frames');
    expect(Array.isArray(data.frames)).toBe(true);
  });
});

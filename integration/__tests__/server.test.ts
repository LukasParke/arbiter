import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { startServers } from '../../src/server.js';
import fetch from 'node-fetch';
import { OpenAPIV3_1 } from 'openapi-types';
import { openApiStore } from '../../src/store/openApiStore.js';
import express from 'express';
import { Server } from 'http';
import bodyParser from 'body-parser';

// Create a mock version of startServers function that operates on our test ports
// This function is no longer needed since we're using the real startServers
// function createMockServer(targetUrl: string, port: number): Server {
//   // ... existing code ...
// }

describe('Server Integration Tests', () => {
  const TARGET_PORT = 3000;
  const PROXY_PORT = 3005; // Changed to avoid conflicts with other tests
  const DOCS_PORT = 3006; // Changed to avoid conflicts with other tests

  const TARGET_URL = `http://localhost:${TARGET_PORT}`;
  const PROXY_URL = `http://localhost:${PROXY_PORT}`;
  const DOCS_URL = `http://localhost:${DOCS_PORT}`;

  let targetServer: any;
  let proxyServer: Server;
  let docsServer: Server;

  beforeAll(async () => {
    // Create a mock target API server
    const targetApp = new Hono();

    // Basic GET endpoint
    targetApp.get('/api/test', (c) => {
      return c.json({ message: 'Test successful' });
    });

    // POST endpoint for users
    targetApp.post('/api/users', async (c) => {
      try {
        const body = await c.req.json();
        c.status(201);
        return c.json({ id: 1, ...body });
      } catch (e) {
        c.status(400);
        return c.json({ error: 'Invalid JSON', message: (e as Error).message });
      }
    });

    // Start the target server
    targetServer = serve({ port: TARGET_PORT, fetch: targetApp.fetch });

    // Clear the OpenAPI store
    openApiStore.clear();

    // Start the real proxy and docs servers
    const servers = await startServers({
      target: TARGET_URL,
      proxyPort: PROXY_PORT,
      docsPort: DOCS_PORT,
      verbose: false,
    });

    proxyServer = servers.proxyServer!;
    docsServer = servers.docsServer!;
  });

  afterAll(async () => {
    // Shutdown servers
    targetServer?.close();
    proxyServer?.close();
    docsServer?.close();
  });

  it('should respond to GET requests and record them', async () => {
    const response = await fetch(`${PROXY_URL}/api/test`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ message: 'Test successful' });

    // Verify that the endpoint was recorded in OpenAPI spec
    const specResponse = await fetch(`${DOCS_URL}/openapi.json`);
    const spec = (await specResponse.json()) as OpenAPIV3_1.Document;
    expect(spec.paths?.['/api/test']?.get).toBeDefined();

    // Verify that the endpoint was recorded in HAR format
    const harResponse = await fetch(`${DOCS_URL}/har`);
    const har = (await harResponse.json()) as { log: { entries: any[] } };
    expect(har.log.entries.length).toBeGreaterThan(0);
    expect(har.log.entries).toContainEqual(
      expect.objectContaining({
        request: expect.objectContaining({
          method: 'GET',
          url: expect.stringContaining('/api/test'),
        }),
      })
    );
  });

  it('should handle POST requests with JSON bodies', async () => {
    const payload = { name: 'Test User', email: 'test@example.com' };

    const response = await fetch(`${PROXY_URL}/api/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body).toEqual({ id: 1, name: 'Test User', email: 'test@example.com' });

    // Verify that the endpoint and request body were recorded
    const specResponse = await fetch(`${DOCS_URL}/openapi.json`);
    const spec = (await specResponse.json()) as OpenAPIV3_1.Document;
    expect(spec.paths?.['/api/users']?.post?.requestBody).toBeDefined();

    // Check that the request schema was generated
    if (spec.paths?.['/api/users']?.post?.requestBody) {
      const requestBody = spec.paths['/api/users'].post
        .requestBody as OpenAPIV3_1.RequestBodyObject;
      if (requestBody.content) {
        expect(requestBody.content['application/json']).toBeDefined();
        expect(requestBody.content['application/json'].schema).toBeDefined();
      }
    }
  });
});

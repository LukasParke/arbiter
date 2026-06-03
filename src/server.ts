import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { createServer } from 'http';
import cors from 'cors';
import zlib from 'zlib';
import { openApiStore, OpenAPIStore } from './store/openApiStore.js';
import { initStorage, storage } from './storage/index.js';
import chalk from 'chalk';
import { IncomingMessage, ServerResponse } from 'http';
import type { SecurityInfo } from './store/openApiStore.js';
import { diffAgainstSpec } from './diff.js';
import bodyParser from 'body-parser';

// Create a simple HAR store
class HARStore {
  private har = {
    log: {
      version: '1.2',
      creator: {
        name: 'Arbiter',
        version: '1.0.0',
      },
      entries: [] as Array<{
        startedDateTime: string;
        time: number;
        request: {
          method: string;
          url: string;
          httpVersion: string;
          headers: Array<{ name: string; value: string }>;
          queryString: Array<{ name: string; value: string }>;
          postData?: any;
        };
        response: {
          status: number;
          statusText: string;
          httpVersion: string;
          headers: Array<{ name: string; value: string }>;
          content: {
            size: number;
            mimeType: string;
            text: string;
          };
        };
        _rawResponseBuffer?: Buffer; // Internal property to store raw data for deferred processing
      }>,
    },
  };

  public getHAR() {
    // Process any deferred entries before returning
    this.processRawBuffers();
    return this.har;
  }

  public addEntry(entry: (typeof this.har.log.entries)[0]) {
    this.har.log.entries.push(entry);
  }

  public clear() {
    this.har.log.entries = [];
  }

  // Process any entries with raw response buffers
  private processRawBuffers() {
    for (const entry of this.har.log.entries) {
      if (entry._rawResponseBuffer && entry.response.content.text === '[Response content stored]') {
        try {
          const buffer = entry._rawResponseBuffer;
          const contentType = entry.response.content.mimeType;

          // Process buffer based on content-encoding header
          const contentEncoding = entry.response.headers.find(
            (h) => h.name.toLowerCase() === 'content-encoding'
          )?.value;

          if (contentEncoding) {
            if (contentEncoding.toLowerCase() === 'gzip') {
              try {
                const decompressed = zlib.gunzipSync(buffer);
                const text = decompressed.toString('utf-8');

                if (contentType.includes('json')) {
                  try {
                    entry.response.content.text = text;
                  } catch (e) {
                    entry.response.content.text = text;
                  }
                } else {
                  entry.response.content.text = text;
                }
              } catch (e) {
                entry.response.content.text = '[Compressed content]';
              }
            } else {
              entry.response.content.text = `[${contentEncoding} compressed content]`;
            }
          } else {
            // For non-compressed responses
            const text = buffer.toString('utf-8');

            if (contentType.includes('json')) {
              try {
                const json = JSON.parse(text);
                entry.response.content.text = JSON.stringify(json);
              } catch (e) {
                entry.response.content.text = text;
              }
            } else {
              entry.response.content.text = text;
            }
          }
        } catch (e) {
          entry.response.content.text = '[Error processing response content]';
        }

        // Remove the raw buffer to free memory
        delete entry._rawResponseBuffer;
      }
    }
  }
}

export const harStore = new HARStore();

/**
 * Server configuration options
 */
export interface ServerOptions {
  target: string;
  proxyPort: number;
  docsPort: number;
  verbose?: boolean;
  dbPath?: string;
  diffAgainst?: string;
}

/**
 * Sets up and starts the proxy and docs servers
 */
export async function startServers({
  target,
  proxyPort,
  docsPort,
  verbose = false,
  dbPath,
  diffAgainst,
}: ServerOptions): Promise<{
  proxyServer: ReturnType<typeof createServer>;
  docsServer: ReturnType<typeof createServer>;
}> {
  // Initialize persistent storage if dbPath provided
  if (dbPath) {
    try {
      await initStorage(dbPath);
      if (verbose) console.log(`Initialized SQLite storage at ${dbPath}`);
      // Hydrate OpenAPI store with persisted endpoints (minimal info)
      const persisted = await storage().getAllEndpoints();
      for (const ep of persisted) {
        try {
          openApiStore.recordEndpoint(ep.path, ep.method.toLowerCase(), ep.data.request, {
            status: ep.data.response?.status || 200,
            headers: ep.data.response?.headers || {},
            contentType: ep.data.response?.contentType || 'application/json',
            body: '[Raw data stored]',
            rawData: Buffer.alloc(0),
          });
        } catch {}
      }
    } catch (e) {
      console.error('Failed to initialize storage:', e);
    }
  }
  // Set the target URL in the OpenAPI store
  openApiStore.setTargetUrl(target);

  // Create proxy app with Express
  const proxyApp = express();
  proxyApp.use(cors());

  // Add body parser for JSON and URL-encoded forms
  proxyApp.use(bodyParser.json({ limit: '10mb' }));
  proxyApp.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
  proxyApp.use(bodyParser.text({ limit: '10mb' }));
  proxyApp.use(bodyParser.raw({ type: 'application/octet-stream', limit: '10mb' }));

  // Create a map to store request bodies
  const requestBodies = new Map<string, any>();

  if (verbose) {
    // Add request logging middleware
    proxyApp.use((req, res, next) => {
      console.log(`Proxying: ${req.method} ${req.url}`);
      next();
    });
  }

  // Create the proxy middleware with explicit type parameters for Express
  const proxyMiddleware = createProxyMiddleware<express.Request, express.Response>({
    target,
    changeOrigin: true,
    secure: false,
    ws: true,
    pathRewrite: (path: string) => path,
    selfHandleResponse: true,
    plugins: [
      (proxyServer, options) => {
        // Handle proxy errors
        proxyServer.on('error', (err, req, res) => {
          console.error('Proxy error:', err);
          if (res instanceof ServerResponse && !res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
          }
        });

        // Handle proxy response
        proxyServer.on('proxyReq', (proxyReq, req, res) => {
          // Store the request body for later use
          if (['POST', 'PUT', 'PATCH'].includes(req.method || '') && req.body) {
            const requestId = `${req.method}-${req.url}-${Date.now()}`;
            requestBodies.set(requestId, req.body);
            // Set a custom header to identify the request
            proxyReq.setHeader('x-request-id', requestId);

            // If the body has been consumed by the body-parser, we need to restream it to the proxy
            if (req.body) {
              const bodyData = JSON.stringify(req.body);
              if (bodyData && bodyData !== '{}') {
                // Update content-length
                proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
                // Write the body to the proxied request
                proxyReq.write(bodyData);
                proxyReq.end();
              }
            }
          }
        });

        proxyServer.on('proxyRes', (proxyRes, req, res) => {
          const startTime = Date.now();
          const chunks: Buffer[] = [];

          // Collect response chunks
          proxyRes.on('data', (chunk: Buffer) => {
            chunks.push(Buffer.from(chunk));
          });

          // When the response is complete
          proxyRes.on('end', () => {
            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Combine response chunks
            const buffer = Buffer.concat(chunks);

            // Set status code
            res.statusCode = proxyRes.statusCode || 200;
            res.statusMessage = proxyRes.statusMessage || '';

            // Copy ALL headers exactly as they are
            Object.keys(proxyRes.headers).forEach((key) => {
              const headerValue = proxyRes.headers[key];
              if (headerValue) {
                res.setHeader(key, headerValue);
              }
            });

            // Send the buffer as the response body without modifying it
            res.end(buffer);

            // Process HAR and OpenAPI data in the background (next event loop tick)
            // to avoid delaying the response to the client
            setImmediate(() => {
              // Get request data
              const method = req.method || 'GET';
              const originalUrl = new URL(`http://${req.headers.host}${req.url}`);
              const path = originalUrl.pathname;

              // Skip web asset requests - don't process JS, CSS, HTML, etc. but keep images and icons
              if (
                path.endsWith('.js') ||
                path.endsWith('.css') ||
                path.endsWith('.html') ||
                path.endsWith('.htm') ||
                path.endsWith('.woff') ||
                path.endsWith('.woff2') ||
                path.endsWith('.ttf') ||
                path.endsWith('.eot') ||
                path.endsWith('.map')
              ) {
                if (verbose) {
                  console.log(`Skipping web asset: ${method} ${path}`);
                }
                return;
              }

              // Skip if contentType is related to web assets, but keep images
              const contentType = proxyRes.headers['content-type'] || '';
              if (
                contentType.includes('javascript') ||
                contentType.includes('css') ||
                contentType.includes('html') ||
                contentType.includes('font/')
              ) {
                if (verbose) {
                  console.log(`Skipping content type: ${method} ${path} (${contentType})`);
                }
                return;
              }

              // Extract query parameters
              const queryParams: Record<string, string> = {};
              const urlSearchParams = new URLSearchParams(originalUrl.search);
              urlSearchParams.forEach((value, key) => {
                queryParams[key] = value;
              });

              // Extract request headers
              const requestHeaders: Record<string, string> = {};
              for (const [key, value] of Object.entries(req.headers)) {
                if (typeof value === 'string') {
                  requestHeaders[key] = value;
                } else if (Array.isArray(value) && value.length > 0) {
                  requestHeaders[key] = value[0];
                }
              }

              // Extract response headers
              const responseHeaders: Record<string, string> = {};
              for (const [key, value] of Object.entries(proxyRes.headers)) {
                if (typeof value === 'string') {
                  responseHeaders[key] = value;
                } else if (Array.isArray(value) && value.length > 0) {
                  responseHeaders[key] = value[0];
                }
              }

              // Get request body from our map if available
              let requestBody = undefined;
              if (['POST', 'PUT', 'PATCH'].includes(method)) {
                const requestId = req.headers['x-request-id'] as string;
                if (requestId && requestBodies.has(requestId)) {
                  requestBody = requestBodies.get(requestId);
                  // Clean up after use
                  requestBodies.delete(requestId);
                } else {
                  // Fallback to req.body
                  requestBody = req.body;
                }
              }

              // Store minimal data for HAR entry - delay expensive processing
              const requestUrl = `${target}${path}${originalUrl.search}`;

              // Create lighter HAR entry with minimal processing
              const harEntry = {
                startedDateTime: new Date(startTime).toISOString(),
                time: responseTime,
                request: {
                  method: method,
                  url: requestUrl,
                  httpVersion: 'HTTP/1.1',
                  headers: Object.entries(requestHeaders)
                    .filter(([key]) => key.toLowerCase() !== 'content-length')
                    .map(([name, value]) => ({ name, value })),
                  queryString: Object.entries(queryParams).map(([name, value]) => ({
                    name,
                    value,
                  })),
                  postData: requestBody
                    ? {
                        mimeType: requestHeaders['content-type'] || 'application/json',
                        text:
                          typeof requestBody === 'string'
                            ? requestBody
                            : JSON.stringify(requestBody),
                      }
                    : undefined,
                },
                response: {
                  status: proxyRes.statusCode || 200,
                  statusText: proxyRes.statusCode === 200 ? 'OK' : 'Error',
                  httpVersion: 'HTTP/1.1',
                  headers: Object.entries(responseHeaders).map(([name, value]) => ({
                    name,
                    value,
                  })),
                  content: {
                    size: buffer.length,
                    mimeType: responseHeaders['content-type'] || 'application/octet-stream',
                    // Store raw buffer and defer text conversion/parsing until needed
                    text: '[Response content stored]',
                  },
                },
                _rawResponseBuffer: buffer, // Store for later processing if needed
              };

              // Add the HAR entry to the store and persist if enabled
              harStore.addEntry(harEntry);
              if (dbPath) {
                storage()
                  .saveHarEntry({
                    startedDateTime: harEntry.startedDateTime,
                    time: harEntry.time,
                    request: harEntry.request,
                    response: {
                      ...harEntry.response,
                      // Do not persist raw buffer reference
                    },
                  })
                  .catch(() => {});
              }

              // Extract security schemes from headers - minimal work
              const securitySchemes: SecurityInfo[] = [];
              if (requestHeaders['x-api-key']) {
                securitySchemes.push({
                  type: 'apiKey' as const,
                  name: 'x-api-key',
                  in: 'header' as const,
                });
              }
              if (requestHeaders['authorization']?.startsWith('Bearer ')) {
                securitySchemes.push({
                  type: 'http' as const,
                  scheme: 'bearer' as const,
                });
              }
              if (requestHeaders['authorization']?.startsWith('Basic ')) {
                securitySchemes.push({
                  type: 'http' as const,
                  scheme: 'basic' as const,
                });
              }

              // Store minimal data in OpenAPI store - just record the endpoint and method
              // This defers schema generation until actually requested
              openApiStore.recordEndpoint(
                path,
                method.toLowerCase(),
                {
                  query: queryParams,
                  headers: requestHeaders,
                  contentType: requestHeaders['content-type'] || 'application/json',
                  body: requestBody, // Now we have the body properly captured
                  security: securitySchemes,
                },
                {
                  status: proxyRes.statusCode || 500,
                  headers: responseHeaders,
                  contentType: responseHeaders['content-type'] || 'application/json',
                  // Store raw data instead of parsed body, but still provide a body property to satisfy the type
                  body: '[Raw data stored]',
                  rawData: buffer,
                }
              );

              // Persist endpoint minimal info for reconstruction
              if (dbPath) {
                storage()
                  .upsertEndpoint(path, method.toLowerCase(), {
                    path,
                    method: method.toLowerCase(),
                    request: {
                      query: queryParams,
                      headers: requestHeaders,
                      contentType: requestHeaders['content-type'] || 'application/json',
                      body: requestBody,
                      security: securitySchemes,
                    },
                    response: {
                      status: proxyRes.statusCode || 500,
                      headers: responseHeaders,
                      contentType: responseHeaders['content-type'] || 'application/json',
                    },
                  })
                  .catch(() => {});
              }

              if (verbose) {
                console.log(`${method} ${path} -> ${proxyRes.statusCode}`);
              }
            }); // End of setImmediate
          });
        });
      },
    ],
  });

  proxyApp.use('/', proxyMiddleware);

  // Create docs app with Express
  const docsApp = express();
  docsApp.use(cors());

  // Create documentation endpoints
  docsApp.get('/har', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (dbPath) {
      try {
        const log = await storage().getHarLog();
        res.send(JSON.stringify(log));
        return;
      } catch {}
    }
    res.send(JSON.stringify(harStore.getHAR()));
  });

  docsApp.get('/traffic.jsonl', async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson');
    const har = harStore.getHAR();
    for (const entry of har.log.entries) {
      const url = new URL(entry.request.url);
      const queryParams: Record<string, string> = {};
      for (const q of entry.request.queryString) {
        queryParams[q.name] = q.value;
      }
      const reqHeaders: Record<string, string> = {};
      for (const h of entry.request.headers) {
        reqHeaders[h.name] = h.value;
      }
      const resHeaders: Record<string, string> = {};
      for (const h of entry.response.headers) {
        resHeaders[h.name] = h.value;
      }
      const line = JSON.stringify({
        timestamp: entry.startedDateTime,
        method: entry.request.method,
        path: url.pathname + url.search,
        request_headers: reqHeaders,
        request_body: entry.request.postData?.text || null,
        response_status: entry.response.status,
        response_headers: resHeaders,
        response_body: entry.response.content.text || null,
      });
      res.write(line + '\n');
    }
    res.end();
  });

  docsApp.get('/openapi.json', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (dbPath) {
      try {
        const persisted = await storage().getAllEndpoints();
        const tempStore = new OpenAPIStore();
        tempStore.setTargetUrl(target);
        for (const ep of persisted) {
          try {
            tempStore.recordEndpoint(ep.path, ep.method.toLowerCase(), ep.data.request, {
              status: ep.data.response?.status || 200,
              headers: ep.data.response?.headers || {},
              contentType: ep.data.response?.contentType || 'application/json',
              body: '[Raw data stored]',
            });
          } catch {}
        }
        res.send(JSON.stringify(tempStore.getOpenAPISpec()));
        return;
      } catch {}
    }
    res.send(JSON.stringify(openApiStore.getOpenAPISpec()));
  });

  docsApp.get('/openapi.yaml', async (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    if (dbPath) {
      try {
        const persisted = await storage().getAllEndpoints();
        const tempStore = new OpenAPIStore();
        tempStore.setTargetUrl(target);
        for (const ep of persisted) {
          try {
            tempStore.recordEndpoint(ep.path, ep.method.toLowerCase(), ep.data.request, {
              status: ep.data.response?.status || 200,
              headers: ep.data.response?.headers || {},
              contentType: ep.data.response?.contentType || 'application/json',
              body: '[Raw data stored]',
            });
          } catch {}
        }
        res.send(tempStore.getOpenAPISpecAsYAML());
        return;
      } catch {}
    }
    res.send(openApiStore.getOpenAPISpecAsYAML());
  });

  docsApp.get('/docs', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`
      <!doctype html>
      <html>
        <head>
          <title>Scalar API Reference</title>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
        </head>
        <body>
          <script id="api-reference" data-url="/openapi.yaml"></script>
          <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
        </body>
      </html>
    `);
  });

  // Diff endpoint
  if (diffAgainst) {
    docsApp.get('/diff', (req, res) => {
      try {
        const result = diffAgainstSpec(diffAgainst);
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify(result, null, 2));
      } catch (e: any) {
        res.status(500).json({ error: 'Diff failed', message: e.message });
      }
    });
  }

  // Home page with links
  docsApp.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>API Documentation</title>
          <style>
            body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            h1 { color: #333; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 10px 0; }
            a { color: #0366d6; text-decoration: none; }
            a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <h1>API Documentation</h1>
          <ul>
            <li><a href="/docs">Swagger UI</a></li>
            <li><a href="/openapi.json">OpenAPI JSON</a></li>
            <li><a href="/openapi.yaml">OpenAPI YAML</a></li>
            <li><a href="/har">HAR Export</a></li>
            <li><a href="/traffic.jsonl">Traffic JSONL</a></li>
            ${diffAgainst ? '<li><a href="/diff">Diff Report</a></li>' : ''}
          </ul>
        </body>
      </html>
    `);
  });

  // Function to check if a port is available
  async function isPortAvailable(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const server = createServer()
        .once('error', () => {
          resolve(false);
        })
        .once('listening', () => {
          server.close();
          resolve(true);
        })
        .listen(port);
    });
  }

  // Function to find an available port
  async function findAvailablePort(startPort: number): Promise<number> {
    let port = startPort;
    while (!(await isPortAvailable(port))) {
      port++;
    }
    return port;
  }

  // Start servers
  const availableProxyPort = await findAvailablePort(proxyPort);
  const availableDocsPort = await findAvailablePort(docsPort);

  if (availableProxyPort !== proxyPort) {
    console.log(
      chalk.yellow(`Port ${proxyPort} is in use, using port ${availableProxyPort} instead`)
    );
  }
  if (availableDocsPort !== docsPort) {
    console.log(
      chalk.yellow(`Port ${docsPort} is in use, using port ${availableDocsPort} instead`)
    );
  }

  // Create HTTP servers
  const proxyServer = createServer(proxyApp);
  const docsServer = createServer(docsApp);

  // WebSocket frame recording
  const wsFrames: Array<{
    timestamp: string;
    path: string;
    direction: 'sent' | 'received';
    data: string;
  }> = [];

  proxyServer.on('upgrade', (request, socket, head) => {
    const path = request.url || '/';
    if (verbose) {
      console.log(`WebSocket upgrade: ${path}`);
    }
    wsFrames.push({
      timestamp: new Date().toISOString(),
      path,
      direction: 'sent',
      data: `[upgrade] ${JSON.stringify(request.headers)}`,
    });

    // Intercept socket data for frame recording
    const originalWrite = socket.write.bind(socket);
    socket.write = (data: any, encoding?: any, cb?: any) => {
      try {
        const text =
          typeof data === 'string'
            ? data
            : Buffer.isBuffer(data)
              ? data.toString('utf-8')
              : String(data);
        wsFrames.push({
          timestamp: new Date().toISOString(),
          path,
          direction: 'sent',
          data: text.length > 10000 ? text.substring(0, 10000) + '...' : text,
        });
      } catch {}
      return originalWrite(data, encoding, cb);
    };

    const originalOnData = socket.on.bind(socket);
    socket.on = (event: any, listener: any) => {
      if (event === 'data') {
        const wrappedListener = (data: any) => {
          try {
            const text =
              typeof data === 'string'
                ? data
                : Buffer.isBuffer(data)
                  ? data.toString('utf-8')
                  : String(data);
            wsFrames.push({
              timestamp: new Date().toISOString(),
              path,
              direction: 'received',
              data: text.length > 10000 ? text.substring(0, 10000) + '...' : text,
            });
          } catch {}
          listener(data);
        };
        return originalOnData(event, wrappedListener);
      }
      return originalOnData(event, listener);
    };
  });

  docsApp.get('/ws', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({ frames: wsFrames }));
  });

  // Start servers
  return new Promise((resolve, reject) => {
    try {
      proxyServer.listen(availableProxyPort, () => {
        docsServer.listen(availableDocsPort, () => {
          console.log('\n' + chalk.green('Arbiter is running! 🚀'));
          console.log('\n' + chalk.bold('Proxy Server:'));
          console.log(chalk.cyan(`  URL: http://localhost:${availableProxyPort}`));
          console.log(chalk.gray(`  Target: ${target}`));
          console.log('\n' + chalk.bold('Documentation:'));
          console.log(chalk.cyan(`  API Reference: http://localhost:${availableDocsPort}/docs`));
          console.log('\n' + chalk.bold('Exports:'));
          console.log(chalk.cyan(`  HAR Export: http://localhost:${availableDocsPort}/har`));
          console.log(
            chalk.cyan(`  OpenAPI JSON: http://localhost:${availableDocsPort}/openapi.json`)
          );
          console.log(
            chalk.cyan(`  OpenAPI YAML: http://localhost:${availableDocsPort}/openapi.yaml`)
          );
          console.log('\n' + chalk.yellow('Press Ctrl+C to stop'));

          resolve({ proxyServer, docsServer });
        });
      });
    } catch (error) {
      reject(error);
    }
  });

}

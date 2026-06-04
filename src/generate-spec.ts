import fs from 'fs';
import { inferSchema, mergeSchemas, type InferredSchema } from './infer.js';
import { stringify as stringifyYAML } from 'yaml';

interface TrafficEntry {
  path: string;
  method: string;
  queryParams?: string[];
  status: number;
  body?: string;
  contentType?: string;
  headers?: Array<{ name: string; value: string }>;
}

interface EndpointGroup {
  path: string;
  method: string;
  queryParams: Set<string>;
  responses: Map<number, { bodies: unknown[]; contentType: string }>;
}

export interface GeneratedSpec {
  openapi: string;
  info: {
    title: string;
    description: string;
    version: string;
  };
  servers: Array<{ url: string; description: string }>;
  paths: Record<string, Record<string, unknown>>;
  components: {
    schemas: Record<string, InferredSchema>;
  };
}

export function generateSpecFromTraffic(
  trafficPath: string,
  options: { title?: string; version?: string; serverUrl?: string } = {}
): GeneratedSpec {
  const raw = fs.readFileSync(trafficPath, 'utf-8');
  const lines = raw.split('\n').filter((l) => l.trim());
  const entries = lines.map((l) => JSON.parse(l) as TrafficEntry);

  // Group by path + method
  const groups = new Map<string, EndpointGroup>();

  for (const entry of entries) {
    const key = `${entry.method}|${entry.path}`;

    if (!groups.has(key)) {
      groups.set(key, {
        path: entry.path,
        method: entry.method,
        queryParams: new Set(),
        responses: new Map(),
      });
    }

    const group = groups.get(key)!;

    // Collect query params
    if (entry.queryParams) {
      for (const qp of entry.queryParams) {
        const paramName = qp.split('=')[0];
        if (paramName) {
          group.queryParams.add(paramName);
        }
      }
    }

    // Collect responses
    if (!group.responses.has(entry.status)) {
      group.responses.set(entry.status, { bodies: [], contentType: entry.contentType || 'application/json' });
    }

    if (entry.body && entry.contentType?.includes('json')) {
      try {
        const body = JSON.parse(entry.body) as unknown;
        group.responses.get(entry.status)!.bodies.push(body);
      } catch {
        // Skip non-JSON bodies
      }
    }
  }

  // Build paths
  const paths: Record<string, Record<string, unknown>> = {};
  const schemas: Record<string, InferredSchema> = {};

  for (const group of groups.values()) {
    if (!paths[group.path]) {
      paths[group.path] = {};
    }

    const parameters: Array<Record<string, unknown>> = [];

    // Query parameters
    for (const paramName of group.queryParams) {
      parameters.push({
        name: paramName,
        in: 'query',
        required: false,
        schema: { type: 'string' },
      });
    }

    // Responses
    const responses: Record<string, unknown> = {};
    for (const [statusCode, { bodies, contentType }] of group.responses) {
      const schemaName = `${group.method.toLowerCase()}_${sanitizePath(group.path)}_${statusCode}`;

      if (bodies.length > 0) {
        const inferred = mergeSchemas(bodies.map((b) => inferSchema(b)));
        schemas[schemaName] = inferred;

        responses[String(statusCode)] = {
          description: `Response for ${group.method} ${group.path}`,
          content: {
            [contentType]: {
              schema: {
                $ref: `#/components/schemas/${schemaName}`,
              },
            },
          },
        };
      } else {
        responses[String(statusCode)] = {
          description: `Response for ${group.method} ${group.path}`,
        };
      }
    }

    const operation: Record<string, unknown> = {
      operationId: `${group.method.toLowerCase()}_${sanitizePath(group.path)}`,
      summary: `${group.method} ${group.path}`,
      responses,
    };

    if (parameters.length > 0) {
      operation.parameters = parameters;
    }

    paths[group.path][group.method.toLowerCase()] = operation;
  }

  // Extract server URL from traffic if not provided
  let serverUrl = options.serverUrl;
  if (!serverUrl && entries.length > 0) {
    const first = entries[0];
    try {
      const url = new URL(first.path, 'http://localhost');
      serverUrl = `${url.protocol}//${url.host}`;
    } catch {
      serverUrl = 'http://localhost';
    }
  }

  return {
    openapi: '3.1.0',
    info: {
      title: options.title || 'Generated API Specification',
      description: 'Auto-generated from captured traffic',
      version: options.version || '1.0.0',
    },
    servers: serverUrl
      ? [{ url: serverUrl, description: 'Target server' }]
      : [],
    paths,
    components: { schemas },
  };
}

function sanitizePath(path: string): string {
  return path
    .replace(/^https?:\/\/[^/]+/, '')
    .replace(/[^a-zA-Z0-9]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
}

export function specToYAML(spec: GeneratedSpec): string {
  return stringifyYAML(spec, { lineWidth: 0, aliasDuplicateObjects: false });
}

export function specToJSON(spec: GeneratedSpec): string {
  return JSON.stringify(spec, null, 2);
}

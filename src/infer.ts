import fs from 'fs';

export interface InferredSchema {
  type?: string | string[];
  properties?: Record<string, InferredSchema>;
  items?: InferredSchema;
  required?: string[];
  description?: string;
  example?: unknown;
  enum?: unknown[];
  format?: string;
  nullable?: boolean;
  additionalProperties?: boolean;
}

export interface EndpointSchema {
  path: string;
  method: string;
  statusCode: number;
  contentType: string;
  schema: InferredSchema;
  sampleCount: number;
}

/**
 * Infer an OpenAPI schema from a JSON value
 */
export function inferSchema(value: unknown, path = ''): InferredSchema {
  if (value === null) {
    return { type: 'null', nullable: true };
  }

  if (typeof value === 'boolean') {
    return { type: 'boolean', example: value };
  }

  if (typeof value === 'number') {
    const isInteger = Number.isInteger(value);
    return {
      type: isInteger ? 'integer' : 'number',
      example: value,
    };
  }

  if (typeof value === 'string') {
    const schema: InferredSchema = { type: 'string', example: value };
    // Detect common formats
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
      schema.format = 'date-time';
    } else if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      schema.format = 'date';
    } else if (/^https?:\/\//.test(value)) {
      schema.format = 'uri';
    } else if (/^[\w.-]+@[\w.-]+\.\w+$/.test(value)) {
      schema.format = 'email';
    } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
      schema.format = 'ipv4';
    } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
      schema.format = 'uuid';
    }
    return schema;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return { type: 'array', items: { type: 'object' } };
    }
    // Infer items schema from all elements and merge
    const itemSchemas = value.map((item) => inferSchema(item, `${path}[]`));
    const mergedItems = mergeSchemas(itemSchemas);
    return { type: 'array', items: mergedItems };
  }

  if (typeof value === 'object' && value !== null) {
    const properties: Record<string, InferredSchema> = {};
    const required: string[] = [];

    for (const [key, val] of Object.entries(value)) {
      properties[key] = inferSchema(val, path ? `${path}.${key}` : key);
      if (val !== null && val !== undefined) {
        required.push(key);
      }
    }

    return {
      type: 'object',
      properties,
      required: required.length > 0 ? required : undefined,
      additionalProperties: false,
    };
  }

  return { type: 'string' };
}

/**
 * Merge multiple schemas into one
 */
export function mergeSchemas(schemas: InferredSchema[]): InferredSchema {
  if (schemas.length === 0) {
    return { type: 'object' };
  }
  if (schemas.length === 1) {
    return schemas[0];
  }

  // Collect all types
  const types = new Set<string>();
  const allProperties: Record<string, InferredSchema[]> = {};
  const allItems: InferredSchema[] = [];
  const allExamples: unknown[] = [];

  for (const s of schemas) {
    if (s.type && typeof s.type === 'string') {
      types.add(s.type);
    }
    if (s.properties) {
      for (const [k, v] of Object.entries(s.properties)) {
        if (!allProperties[k]) {allProperties[k] = [];}
        allProperties[k].push(v);
      }
    }
    if (s.items) {
      allItems.push(s.items);
    }
    if (s.example !== undefined) {
      allExamples.push(s.example);
    }
  }

  const result: InferredSchema = {};

  // Handle type merging
  const typeArray = Array.from(types);
  if (typeArray.length === 1) {
    result.type = typeArray[0];
  } else if (typeArray.length > 1) {
    // If both null and another type, use nullable
    if (typeArray.includes('null') && typeArray.length === 2) {
      result.type = typeArray.find((t) => t !== 'null') || 'string';
      result.nullable = true;
    } else {
      result.type = typeArray;
    }
  }

  // Merge object properties
  if (Object.keys(allProperties).length > 0) {
    result.properties = {};
    for (const [key, propSchemas] of Object.entries(allProperties)) {
      result.properties[key] = mergeSchemas(propSchemas);
    }
    // Required if present in all schemas
    result.required = Object.keys(allProperties).filter((key) =>
      schemas.every((s) => s.properties && key in s.properties)
    );
    if (result.required.length === 0) {
      delete result.required;
    }
    result.additionalProperties = false;
  }

  // Merge array items
  if (allItems.length > 0) {
    result.items = mergeSchemas(allItems);
  }

  // Use first example
  if (allExamples.length > 0) {
    result.example = allExamples[0];
  }

  return result;
}

/**
 * Infer schemas from a traffic JSONL file
 */
export function inferFromTraffic(trafficPath: string): EndpointSchema[] {
  const raw = fs.readFileSync(trafficPath, 'utf-8');
  const lines = raw.split('\n').filter((l) => l.trim());

  // Group responses by endpoint
  const endpointMap = new Map<
    string,
    { path: string; method: string; statusCode: number; contentType: string; bodies: unknown[] }
  >();

  for (const line of lines) {
    const entry = JSON.parse(line) as {
      path: string;
      method: string;
      status: number;
      contentType?: string;
      body?: string;
    };

    if (!entry.body || !entry.contentType?.includes('json')) {
      continue;
    }

    try {
      const body = JSON.parse(entry.body) as unknown;
      const key = `${entry.method}|${entry.path}|${entry.status}`;

      if (!endpointMap.has(key)) {
        endpointMap.set(key, {
          path: entry.path,
          method: entry.method,
          statusCode: entry.status,
          contentType: entry.contentType || 'application/json',
          bodies: [],
        });
      }
      endpointMap.get(key)!.bodies.push(body);
    } catch {
      // Skip non-JSON bodies
    }
  }

  const results: EndpointSchema[] = [];
  for (const { path, method, statusCode, contentType, bodies } of endpointMap.values()) {
    if (bodies.length === 0) {continue;}

    const schemas = bodies.map((b) => inferSchema(b));
    const merged = mergeSchemas(schemas);

    results.push({
      path,
      method,
      statusCode,
      contentType,
      schema: merged,
      sampleCount: bodies.length,
    });
  }

  return results;
}

/**
 * Format inferred schemas as OpenAPI components
 */
export function formatAsComponents(endpoints: EndpointSchema[]): string {
  const lines: string[] = [];
  lines.push('components:');
  lines.push('  schemas:');

  for (const ep of endpoints) {
    const name = schemaNameFromEndpoint(ep);
    lines.push(`    ${name}:`);
    lines.push(...formatSchema(ep.schema, '      '));
  }

  return lines.join('\n');
}

function schemaNameFromEndpoint(ep: EndpointSchema): string {
  // Generate a schema name from path and status
  const pathParts = ep.path
    .replace(/^https?:\/\/[^/]+/, '')
    .split('/')
    .filter((p) => p && !p.match(/^\{.*\}$/))
    .map((p) => p.replace(/[^a-zA-Z0-9]/g, '_'));

  const base = pathParts.length > 0 ? pathParts.join('_') : 'root';
  return `${ep.method.toLowerCase()}_${base}_${ep.statusCode}_response`;
}

function formatSchema(schema: InferredSchema, indent: string): string[] {
  const lines: string[] = [];

  if (schema.type) {
    lines.push(`${indent}type: ${Array.isArray(schema.type) ? schema.type.join(', ') : schema.type}`);
  }

  if (schema.nullable) {
    lines.push(`${indent}nullable: true`);
  }

  if (schema.format) {
    lines.push(`${indent}format: ${schema.format}`);
  }

  if (schema.example !== undefined) {
    const ex = JSON.stringify(schema.example);
    lines.push(`${indent}example: ${ex}`);
  }

  if (schema.properties) {
    lines.push(`${indent}properties:`);
    for (const [key, prop] of Object.entries(schema.properties)) {
      lines.push(`${indent}  ${key}:`);
      lines.push(...formatSchema(prop, `${indent}    `));
    }
  }

  if (schema.required && schema.required.length > 0) {
    lines.push(`${indent}required:`);
    for (const req of schema.required) {
      lines.push(`${indent}  - ${req}`);
    }
  }

  if (schema.items) {
    lines.push(`${indent}items:`);
    lines.push(...formatSchema(schema.items, `${indent}  `));
  }

  if (schema.additionalProperties !== undefined) {
    lines.push(`${indent}additionalProperties: ${schema.additionalProperties}`);
  }

  return lines;
}

import fs from 'fs';
import type { OpenAPIV3_1 } from 'openapi-types';
import { parse as parseYAML } from 'yaml';
import { openApiStore } from './store/openApiStore.js';

export interface DiffResult {
  summary: {
    endpointsInSpec: number;
    endpointsCaptured: number;
    missingFromSpec: number;
    untestedInSpec: number;
    queryParamGaps: number;
  };
  missingEndpoints: Array<{ path: string; method: string; queryParamsSeen: string[] }>;
  untestedEndpoints: Array<{ path: string; method: string }>;
  queryParamGaps: Array<{ path: string; method: string; missingQueryParams: string[] }>;
}

export interface SchemaGap {
  path: string;
  method: string;
  operationId: string;
  category: 'missing-response-schema' | 'missing-request-schema' | 'bare-response-schema' | 'missing-param-schema';
  detail: string;
}

export interface SchemaValidationResult {
  summary: {
    totalEndpoints: number;
    missingResponseSchemas: number;
    missingRequestSchemas: number;
    bareResponseSchemas: number;
    missingParamSchemas: number;
    totalGaps: number;
  };
  gaps: SchemaGap[];
}

function normalizePath(path: string): string {
  return path
    .replace(
      /\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/g,
      '/{guid}'
    )
    .replace(/\/([0-9a-zA-Z_-]{30,})/g, '/{key}')
    .replace(/\/(\d+)/g, '/{id}');
}

function extractSpecPaths(spec: OpenAPIV3_1.Document): Set<string> {
  const set = new Set<string>();
  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    if (!methods) {
      continue;
    }
    const norm = normalizePath(path);
    for (const method of Object.keys(methods)) {
      if (['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) {
        set.add(`${norm}|${method.toUpperCase()}`);
      }
    }
  }
  return set;
}

function extractCapturedPaths(store: typeof openApiStore): {
  captured: Set<string>;
  queryParams: Map<string, Set<string>>;
} {
  const spec = store.getOpenAPISpec();
  const captured = new Set<string>();
  const queryParams = new Map<string, Set<string>>();

  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    if (!methods) {
      continue;
    }
    const norm = normalizePath(path);
    for (const [method, operation] of Object.entries(methods)) {
      if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) {
        continue;
      }
      const key = `${norm}|${method.toUpperCase()}`;
      captured.add(key);

      const op = operation as OpenAPIV3_1.OperationObject;
      const seen = new Set<string>();
      for (const param of op.parameters || []) {
        const p = param as OpenAPIV3_1.ParameterObject;
        if (p.in === 'query' && p.name) {
          seen.add(p.name);
        }
      }
      queryParams.set(key, seen);
    }
  }

  return { captured, queryParams };
}

export function diffAgainstSpec(specPath: string): DiffResult {
  const raw = fs.readFileSync(specPath, 'utf-8');
  let existingSpec: OpenAPIV3_1.Document;
  if (specPath.endsWith('.yaml') || specPath.endsWith('.yml')) {
    existingSpec = parseYAML(raw) as OpenAPIV3_1.Document;
  } else {
    existingSpec = JSON.parse(raw) as OpenAPIV3_1.Document;
  }
  const specPaths = extractSpecPaths(existingSpec);

  const { captured, queryParams } = extractCapturedPaths(openApiStore);

  const missing = new Set<string>();
  const untested = new Set<string>();

  for (const cap of captured) {
    if (!specPaths.has(cap)) {
      missing.add(cap);
    }
  }

  for (const spec of specPaths) {
    if (!captured.has(spec)) {
      untested.add(spec);
    }
  }

  const missingEndpoints = Array.from(missing).map((key) => {
    const [path, method] = key.split('|');
    return {
      path,
      method,
      queryParamsSeen: Array.from(queryParams.get(key) || []).sort(),
    };
  });

  const untestedEndpoints = Array.from(untested).map((key) => {
    const [path, method] = key.split('|');
    return { path, method };
  });

  // Query param gaps: for paths present in both, which query params are in captured but not in spec?
  const paramGaps: Array<{ path: string; method: string; missingQueryParams: string[] }> = [];
  for (const key of specPaths) {
    if (!captured.has(key)) {
      continue;
    }
    const [path, method] = key.split('|');

    const pathEntry = Object.entries(existingSpec.paths || {}).find(
      ([p]) => normalizePath(p) === path
    );
    const existingOp = pathEntry ? pathEntry[1] : undefined;
    if (!existingOp) {
      continue;
    }

    const specParams = new Set<string>();
    for (const param of existingOp.parameters || []) {
      const p = param as OpenAPIV3_1.ParameterObject;
      if (p.in === 'query' && p.name) {
        specParams.add(p.name);
      }
    }

    const seen = queryParams.get(key) || new Set<string>();
    const missingParams = Array.from(seen).filter((p) => !specParams.has(p));
    if (missingParams.length > 0) {
      paramGaps.push({ path, method, missingQueryParams: missingParams.sort() });
    }
  }

  return {
    summary: {
      endpointsInSpec: specPaths.size,
      endpointsCaptured: captured.size,
      missingFromSpec: missingEndpoints.length,
      untestedInSpec: untestedEndpoints.length,
      queryParamGaps: paramGaps.length,
    },
    missingEndpoints: missingEndpoints.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
    untestedEndpoints: untestedEndpoints.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
    queryParamGaps: paramGaps.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
  };
}

export function writeDiffReport(result: DiffResult, outputPath: string): void {
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
}

export function diffFromTraffic(specPath: string, trafficPath: string): DiffResult {
  const raw = fs.readFileSync(specPath, 'utf-8');
  let existingSpec: OpenAPIV3_1.Document;
  if (specPath.endsWith('.yaml') || specPath.endsWith('.yml')) {
    existingSpec = parseYAML(raw) as OpenAPIV3_1.Document;
  } else {
    existingSpec = JSON.parse(raw) as OpenAPIV3_1.Document;
  }
  const specPaths = extractSpecPaths(existingSpec);

  const captured = new Set<string>();
  const queryParams = new Map<string, Set<string>>();

  const trafficRaw = fs.readFileSync(trafficPath, 'utf-8');
  const lines = trafficRaw.split('\n').filter((line) => line.trim());

  for (const line of lines) {
    const entry = JSON.parse(line) as { path: string; method: string; queryParams?: string[] };
    const url = new URL(entry.path, 'http://localhost');
    const norm = normalizePath(url.pathname);
    const method = entry.method.toUpperCase();
    const key = `${norm}|${method}`;
    captured.add(key);

    const seen = queryParams.get(key) || new Set<string>();
    if (entry.queryParams) {
      for (const qp of entry.queryParams) {
        seen.add(qp);
      }
    } else {
      url.searchParams.forEach((_value, name) => {
        seen.add(name);
      });
    }
    queryParams.set(key, seen);
  }

  const missing = new Set<string>();
  const untested = new Set<string>();

  for (const cap of captured) {
    if (!specPaths.has(cap)) {
      missing.add(cap);
    }
  }

  for (const spec of specPaths) {
    if (!captured.has(spec)) {
      untested.add(spec);
    }
  }

  const missingEndpoints = Array.from(missing).map((key) => {
    const [path, method] = key.split('|');
    return {
      path,
      method,
      queryParamsSeen: Array.from(queryParams.get(key) || []).sort(),
    };
  });

  const untestedEndpoints = Array.from(untested).map((key) => {
    const [path, method] = key.split('|');
    return { path, method };
  });

  const paramGaps: Array<{ path: string; method: string; missingQueryParams: string[] }> = [];
  for (const key of specPaths) {
    if (!captured.has(key)) {
      continue;
    }
    const [path, method] = key.split('|');

    const pathEntry = Object.entries(existingSpec.paths || {}).find(
      ([p]) => normalizePath(p) === path
    );
    const existingOp = pathEntry ? pathEntry[1] : undefined;
    if (!existingOp) {
      continue;
    }

    const specParams = new Set<string>();
    for (const param of existingOp.parameters || []) {
      const p = param as OpenAPIV3_1.ParameterObject;
      if (p.in === 'query' && p.name) {
        specParams.add(p.name);
      }
    }

    const seen = queryParams.get(key) || new Set<string>();
    const missingParams = Array.from(seen).filter((p) => !specParams.has(p));
    if (missingParams.length > 0) {
      paramGaps.push({ path, method, missingQueryParams: missingParams.sort() });
    }
  }

  return {
    summary: {
      endpointsInSpec: specPaths.size,
      endpointsCaptured: captured.size,
      missingFromSpec: missingEndpoints.length,
      untestedInSpec: untestedEndpoints.length,
      queryParamGaps: paramGaps.length,
    },
    missingEndpoints: missingEndpoints.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
    untestedEndpoints: untestedEndpoints.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
    queryParamGaps: paramGaps.sort((a, b) =>
      `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)
    ),
  };
}

export function validateSchemaCoverage(specPath: string): SchemaValidationResult {
  const raw = fs.readFileSync(specPath, 'utf-8');
  let spec: OpenAPIV3_1.Document;
  if (specPath.endsWith('.yaml') || specPath.endsWith('.yml')) {
    spec = parseYAML(raw) as OpenAPIV3_1.Document;
  } else {
    spec = JSON.parse(raw) as OpenAPIV3_1.Document;
  }

  const gaps: SchemaGap[] = [];
  let totalEndpoints = 0;

  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    if (!methods) {continue;}
    for (const [method, operation] of Object.entries(methods)) {
      if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) {
        continue;
      }
      totalEndpoints++;
      const op = operation as OpenAPIV3_1.OperationObject;
      const opId = op.operationId || 'unknown';

      // Check response schemas
      const responses = op.responses || {};
      for (const [code, resp] of Object.entries(responses)) {
        if (code === '204' || code === '101') {continue;}
        const response = resp as OpenAPIV3_1.ResponseObject;

        if (!response.content || Object.keys(response.content).length === 0) {
          if (!('$ref' in response)) {
            gaps.push({
              path,
              method: method.toUpperCase(),
              operationId: opId,
              category: 'missing-response-schema',
              detail: `Response ${code} has no content schema`,
            });
          }
          continue;
        }

        for (const [mediaType, media] of Object.entries(response.content)) {
          const schema = (media).schema;
          if (!schema) {
            gaps.push({
              path,
              method: method.toUpperCase(),
              operationId: opId,
              category: 'missing-response-schema',
              detail: `Response ${code} (${mediaType}) has empty schema`,
            });
          } else if (
            'type' in schema &&
            schema.type === 'object' &&
            !('properties' in schema) &&
            !('allOf' in schema) &&
            !('$ref' in schema)
          ) {
            gaps.push({
              path,
              method: method.toUpperCase(),
              operationId: opId,
              category: 'bare-response-schema',
              detail: `Response ${code} (${mediaType}) has bare type:object with no properties`,
            });
          }
        }
      }

      // Check request body schemas
      const requestBody = op.requestBody as OpenAPIV3_1.RequestBodyObject | undefined;
      if (requestBody && requestBody.content) {
        for (const [mediaType, media] of Object.entries(requestBody.content)) {
          const schema = (media).schema;
          if (!schema) {
            gaps.push({
              path,
              method: method.toUpperCase(),
              operationId: opId,
              category: 'missing-request-schema',
              detail: `Request body (${mediaType}) has no schema`,
            });
          } else if (
            'type' in schema &&
            schema.type === 'object' &&
            !('properties' in schema) &&
            !('allOf' in schema) &&
            !('$ref' in schema)
          ) {
            gaps.push({
              path,
              method: method.toUpperCase(),
              operationId: opId,
              category: 'missing-request-schema',
              detail: `Request body (${mediaType}) has bare type:object with no properties`,
            });
          }
        }
      }

      // Check parameter schemas
      for (const param of op.parameters || []) {
        const p = param as OpenAPIV3_1.ParameterObject;
        if ('$ref' in p) {continue;} // skip refs
        const pSchema = p.schema;
        if (!pSchema) {
          gaps.push({
            path,
            method: method.toUpperCase(),
            operationId: opId,
            category: 'missing-param-schema',
            detail: `Parameter "${p.name}" has no schema`,
          });
        } else if (
          'type' in pSchema &&
          !pSchema.type &&
          !('$ref' in pSchema)
        ) {
          gaps.push({
            path,
            method: method.toUpperCase(),
            operationId: opId,
            category: 'missing-param-schema',
            detail: `Parameter "${p.name}" has empty schema`,
          });
        }
      }
    }
  }

  const missingResponse = gaps.filter((g) => g.category === 'missing-response-schema').length;
  const missingRequest = gaps.filter((g) => g.category === 'missing-request-schema').length;
  const bareResponse = gaps.filter((g) => g.category === 'bare-response-schema').length;
  const missingParam = gaps.filter((g) => g.category === 'missing-param-schema').length;

  return {
    summary: {
      totalEndpoints,
      missingResponseSchemas: missingResponse,
      missingRequestSchemas: missingRequest,
      bareResponseSchemas: bareResponse,
      missingParamSchemas: missingParam,
      totalGaps: gaps.length,
    },
    gaps: gaps.sort((a, b) => `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)),
  };
}

export function writeSchemaValidationReport(result: SchemaValidationResult, outputPath: string): void {
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
}

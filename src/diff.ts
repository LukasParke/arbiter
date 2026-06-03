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

function normalizePath(path: string): string {
  return path
    .replace(/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/g, '/{guid}')
    .replace(/\/([0-9a-zA-Z_-]{30,})/g, '/{key}')
    .replace(/\/(\d+)/g, '/{id}');
}

function extractSpecPaths(spec: OpenAPIV3_1.Document): Set<string> {
  const set = new Set<string>();
  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    if (!methods) continue;
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
    if (!methods) continue;
    const norm = normalizePath(path);
    for (const [method, operation] of Object.entries(methods)) {
      if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) continue;
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
    existingSpec = JSON.parse(raw);
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
    if (!captured.has(key)) continue;
    const [path, method] = key.split('|');

    const existingOp = Object.entries(existingSpec.paths || {}).find(([p]) => normalizePath(p) === path)?.[1] as OpenAPIV3_1.OperationObject | undefined;
    if (!existingOp) continue;

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
    missingEndpoints: missingEndpoints.sort((a, b) => `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)),
    untestedEndpoints: untestedEndpoints.sort((a, b) => `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)),
    queryParamGaps: paramGaps.sort((a, b) => `${a.path}|${a.method}`.localeCompare(`${b.path}|${b.method}`)),
  };
}

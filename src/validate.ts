import fs from 'fs';
import type { OpenAPIV3_1 } from 'openapi-types';
import { parse as parseYAML } from 'yaml';

export interface ValidationViolation {
  type: 'request' | 'response';
  path: string;
  method: string;
  message: string;
  detail?: string;
}

export interface ValidationResult {
  valid: boolean;
  violations: ValidationViolation[];
}

export class SpecValidator {
  private spec: OpenAPIV3_1.Document;
  private pathTemplates: Map<RegExp, string> = new Map();

  constructor(specPath: string) {
    const raw = fs.readFileSync(specPath, 'utf-8');
    if (specPath.endsWith('.yaml') || specPath.endsWith('.yml')) {
      this.spec = parseYAML(raw) as OpenAPIV3_1.Document;
    } else {
      this.spec = JSON.parse(raw) as OpenAPIV3_1.Document;
    }
    this.buildPathTemplates();
  }

  private buildPathTemplates(): void {
    const paths = this.spec.paths || {};
    for (const path of Object.keys(paths)) {
      const pattern = path
        .replace(/\{/g, '(?<{\\w+}>[^/]+)')
        .replace(/\}/g, '')
        .replace(/\//g, '\\/');
      this.pathTemplates.set(new RegExp(`^${pattern}$`), path);
    }
  }

  private matchPath(incomingPath: string): string | undefined {
    for (const [regex, specPath] of this.pathTemplates) {
      if (regex.test(incomingPath)) {
        return specPath;
      }
    }
    return undefined;
  }

  validateRequest(
    path: string,
    method: string,
    queryParams: Record<string, string>,
    headers: Record<string, string>
  ): ValidationResult {
    const violations: ValidationViolation[] = [];
    const specPath = this.matchPath(path);

    if (!specPath) {
      violations.push({
        type: 'request',
        path,
        method: method.toUpperCase(),
        message: 'Path not found in spec',
      });
      return { valid: false, violations };
    }

    const pathObj = this.spec.paths?.[specPath];
    if (!pathObj) {
      violations.push({
        type: 'request',
        path,
        method: method.toUpperCase(),
        message: 'Path object not found in spec',
      });
      return { valid: false, violations };
    }

    const operation = pathObj[method.toLowerCase() as keyof OpenAPIV3_1.PathItemObject] as
      | OpenAPIV3_1.OperationObject
      | undefined;

    if (!operation) {
      violations.push({
        type: 'request',
        path: specPath,
        method: method.toUpperCase(),
        message: `Method ${method.toUpperCase()} not defined for path`,
      });
      return { valid: false, violations };
    }

    // Validate required parameters
    for (const param of operation.parameters || []) {
      const p = param as OpenAPIV3_1.ParameterObject;
      if (p.required) {
        if (p.in === 'query' && !queryParams[p.name]) {
          violations.push({
            type: 'request',
            path: specPath,
            method: method.toUpperCase(),
            message: `Missing required query parameter: ${p.name}`,
          });
        }
        if (p.in === 'header' && !headers[p.name.toLowerCase()]) {
          violations.push({
            type: 'request',
            path: specPath,
            method: method.toUpperCase(),
            message: `Missing required header: ${p.name}`,
          });
        }
      }
    }

    return { valid: violations.length === 0, violations };
  }

  validateResponse(
    path: string,
    method: string,
    statusCode: number,
    contentType: string,
    body: unknown
  ): ValidationResult {
    const violations: ValidationViolation[] = [];
    const specPath = this.matchPath(path);

    if (!specPath) {
      return { valid: false, violations };
    }

    const pathObj = this.spec.paths?.[specPath];
    if (!pathObj) {
      return { valid: false, violations };
    }

    const operation = pathObj[method.toLowerCase() as keyof OpenAPIV3_1.PathItemObject] as
      | OpenAPIV3_1.OperationObject
      | undefined;

    if (!operation) {
      return { valid: false, violations };
    }

    const responses = operation.responses || {};
    const statusStr = String(statusCode);
    const response = responses[statusStr] as OpenAPIV3_1.ResponseObject | undefined;

    if (!response) {
      violations.push({
        type: 'response',
        path: specPath,
        method: method.toUpperCase(),
        message: `Status code ${statusCode} not documented in spec`,
      });
      return { valid: false, violations };
    }

    // For JSON responses, do basic schema validation
    if (contentType.includes('json') && body !== undefined && body !== null) {
      const media = response.content?.[contentType] || response.content?.['application/json'];
      if (media) {
        const schema = (media).schema;
        if (schema) {
          const schemaViolations = this.validateValueAgainstSchema(body, schema, '');
          for (const v of schemaViolations) {
            violations.push({
              type: 'response',
              path: specPath,
              method: method.toUpperCase(),
              message: `Schema violation: ${v}`,
            });
          }
        }
      }
    }

    return { valid: violations.length === 0, violations };
  }

  private validateValueAgainstSchema(
    value: unknown,
    schema: OpenAPIV3_1.SchemaObject,
    path: string
  ): string[] {
    const violations: string[] = [];

    if ('$ref' in schema && schema.$ref && typeof schema.$ref === 'string') {
      const refName = schema.$ref.split('/').pop();
      const refSchema = this.spec.components?.schemas?.[refName || ''];
      if (refSchema) {
        return this.validateValueAgainstSchema(value, refSchema, path);
      }
      return violations;
    }

    const stype = schema.type;

    if (stype === 'object' && typeof value === 'object' && value !== null) {
      // Check required properties
      for (const req of schema.required || []) {
        if (!(req in value)) {
          violations.push(`${path || 'root'}: missing required property "${req}"`);
        }
      }
      // Validate known properties
      for (const [propName, propSchema] of Object.entries(schema.properties || {})) {
        const propValue = (value as Record<string, unknown>)[propName];
        if (propValue !== undefined) {
          violations.push(
            ...this.validateValueAgainstSchema(
              propValue,
              propSchema,
              path ? `${path}.${propName}` : propName
            )
          );
        }
      }
    } else if (stype === 'array' && Array.isArray(value)) {
      const itemsSchema = schema.items as OpenAPIV3_1.SchemaObject | undefined;
      if (itemsSchema) {
        for (let i = 0; i < value.length; i++) {
          violations.push(
            ...this.validateValueAgainstSchema(value[i], itemsSchema, `${path}[${i}]`)
          );
        }
      }
    } else if (stype === 'string' && typeof value !== 'string') {
      violations.push(`${path || 'root'}: expected string, got ${typeof value}`);
    } else if (stype === 'integer' && typeof value !== 'number') {
      violations.push(`${path || 'root'}: expected integer, got ${typeof value}`);
    } else if (stype === 'number' && typeof value !== 'number') {
      violations.push(`${path || 'root'}: expected number, got ${typeof value}`);
    } else if (stype === 'boolean' && typeof value !== 'boolean') {
      violations.push(`${path || 'root'}: expected boolean, got ${typeof value}`);
    }

    return violations;
  }
}

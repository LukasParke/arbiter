import fs from 'fs';
import path from 'path';
import { stringify } from 'yaml';
import type { OpenAPI, OpenAPIV3_1 } from 'openapi-types';
import zlib from 'zlib';

export interface SecurityInfo {
  type: 'apiKey' | 'oauth2' | 'http' | 'openIdConnect';
  name?: string;
  in?: 'header' | 'query' | 'cookie';
  scheme?: string;
  flows?: {
    implicit?: {
      authorizationUrl: string;
      scopes: Record<string, string>;
    };
    authorizationCode?: {
      authorizationUrl: string;
      tokenUrl: string;
      scopes: Record<string, string>;
    };
    clientCredentials?: {
      tokenUrl: string;
      scopes: Record<string, string>;
    };
    password?: {
      tokenUrl: string;
      scopes: Record<string, string>;
    };
  };
  openIdConnectUrl?: string;
}

interface RequestInfo {
  query: Record<string, string>;
  body: any;
  contentType: string;
  headers?: Record<string, string>;
  security?: SecurityInfo[];
}

interface ResponseInfo {
  status: number;
  body: any;
  contentType: string;
  headers?: Record<string, string>;
  rawData?: Buffer;
}

interface EndpointInfo {
  path: string;
  method: string;
  responses: {
    [key: string | number]: OpenAPIV3_1.ResponseObject;
  };
  parameters: OpenAPIV3_1.ParameterObject[];
  requestBody?: OpenAPIV3_1.RequestBodyObject;
  security?: OpenAPIV3_1.SecurityRequirementObject[];
}

interface HAREntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: Array<{ name: string; value: string }>;
    queryString: Array<{ name: string; value: string }>;
    postData?: {
      mimeType: string;
      text: string;
    };
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
}

type PathItemObject = {
  [method: string]: OpenAPIV3_1.OperationObject;
};

type PathsObject = {
  [path: string]: PathItemObject;
};

// Define interface for raw response data
interface RawResponseData {
  rawData: string;
  status: number;
  headers?: Record<string, string>;
  method?: string;
  url?: string;
}

// Define type for raw data cache - using Maps for better TypeScript support
type RawDataCacheType = Map<string, Map<string, RawResponseData>>;

export class OpenAPIStore {
  private openAPIObject: OpenAPIV3_1.Document | null = null;
  private endpoints = new Map<string, EndpointInfo>();
  private harEntries: HAREntry[] = [];
  private targetUrl: string;
  private examples = new Map<string, any[]>();
  private schemaCache = new Map<string, OpenAPIV3_1.SchemaObject[]>();
  private securitySchemes = new Map<string, OpenAPIV3_1.SecuritySchemeObject>();
  private rawDataCache: RawDataCacheType = new Map();

  constructor(targetUrl = 'http://localhost:3000') {
    this.targetUrl = targetUrl;
    this.openAPIObject = {
      openapi: '3.1.0',
      info: {
        title: 'API Documentation',
        version: '1.0.0',
      },
      paths: {},
      components: {
        schemas: {},
        securitySchemes: {},
      },
    };
  }

  public setTargetUrl(url: string): void {
    this.targetUrl = url;
  }

  public clear(): void {
    this.endpoints.clear();
    this.harEntries = [];
    this.examples.clear();
    this.schemaCache.clear();
    this.securitySchemes.clear();
    this.rawDataCache.clear();
  }

  // Persist/restore helpers
  public getEndpoint(path: string, method: string): EndpointInfo | undefined {
    const key = `${method.toLowerCase()} ${path}`;
    return this.endpoints.get(key);
  }

  public importEndpoint(path: string, method: string, data: EndpointInfo): void {
    const key = `${method.toLowerCase()} ${path}`;
    this.endpoints.set(key, data);
  }

  private deepMergeSchemas(schemas: OpenAPIV3_1.SchemaObject[]): OpenAPIV3_1.SchemaObject {
    if (schemas.length === 0) return { type: 'object' };
    if (schemas.length === 1) return schemas[0];

    // If all schemas are objects, merge their properties
    if (schemas.every((s) => s.type === 'object')) {
      const mergedProperties: Record<string, OpenAPIV3_1.SchemaObject> = {};
      const mergedRequired: string[] = [];

      schemas.forEach((schema) => {
        if (schema.properties) {
          Object.entries(schema.properties).forEach(([key, value]) => {
            if (!mergedProperties[key]) {
              mergedProperties[key] = value;
            } else {
              // If property exists, merge its schemas
              mergedProperties[key] = this.deepMergeSchemas([mergedProperties[key], value]);
            }
          });
        }
      });

      return {
        type: 'object',
        properties: mergedProperties,
      };
    }

    // If schemas are different types, use oneOf with unique schemas
    const uniqueSchemas = schemas.filter(
      (schema, index, self) =>
        index === self.findIndex((s) => JSON.stringify(s) === JSON.stringify(schema))
    );

    if (uniqueSchemas.length === 1) {
      return uniqueSchemas[0];
    }

    return {
      type: 'object',
      oneOf: uniqueSchemas,
    };
  }

  private generateJsonSchema(obj: any): OpenAPIV3_1.SchemaObject {
    if (obj === null) return { type: 'null' };
    if (Array.isArray(obj)) {
      if (obj.length === 0) return { type: 'array', items: { type: 'object' } };

      // Check if all items are objects with similar structure
      const allObjects = obj.every(
        (item) => typeof item === 'object' && item !== null && !Array.isArray(item)
      );

      if (allObjects) {
        // Generate a schema for the first object
        const firstObjectSchema = this.generateJsonSchema(obj[0]);

        // Use that as a template for all items
        return {
          type: 'array',
          items: firstObjectSchema,
          example: obj,
        };
      }

      // Check if all items are primitives of the same type
      if (
        obj.length > 0 &&
        obj.every(
          (item) =>
            typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean'
        )
      ) {
        // Handle arrays of primitives
        const firstItemType = typeof obj[0];
        if (obj.every((item) => typeof item === firstItemType)) {
          // For numbers, check if they're all integers
          if (firstItemType === 'number') {
            const isAllIntegers = obj.every(Number.isInteger);
            return {
              type: 'array',
              items: {
                type: isAllIntegers ? 'integer' : 'number',
              },
              example: obj,
            };
          }

          // For strings and booleans
          return {
            type: 'array',
            items: {
              type: firstItemType as OpenAPIV3_1.NonArraySchemaObjectType,
            },
            example: obj,
          };
        }
      }

      // Generate schemas for all items
      const itemSchemas = obj.map((item) => this.generateJsonSchema(item));

      // If all items have the same schema, use that
      if (itemSchemas.every((s) => JSON.stringify(s) === JSON.stringify(itemSchemas[0]))) {
        return {
          type: 'array',
          items: itemSchemas[0],
          example: obj,
        };
      }

      // If items have different schemas, use oneOf
      return {
        type: 'array',
        items: {
          type: 'object',
          oneOf: itemSchemas,
        },
        example: obj,
      };
    }

    if (typeof obj === 'object') {
      const properties: Record<string, OpenAPIV3_1.SchemaObject> = {};
      for (const [key, value] of Object.entries(obj)) {
        properties[key] = this.generateJsonSchema(value);
      }
      return {
        type: 'object',
        properties,
        example: obj,
      };
    }

    // Special handling for numbers to distinguish between integer and number
    if (typeof obj === 'number') {
      // Check if the number is an integer
      if (Number.isInteger(obj)) {
        return {
          type: 'integer',
          example: obj,
        };
      }
      return {
        type: 'number',
        example: obj,
      };
    }

    // Map JavaScript types to OpenAPI types
    const typeMap: Record<string, OpenAPIV3_1.NonArraySchemaObjectType> = {
      string: 'string',
      boolean: 'boolean',
      bigint: 'integer',
      symbol: 'string',
      undefined: 'string',
      function: 'string',
    };

    return {
      type: typeMap[typeof obj] || 'string',
      example: obj,
    };
  }

  private recordHAREntry(
    path: string,
    method: string,
    request: RequestInfo,
    response: ResponseInfo
  ): void {
    const now = new Date();
    const url = new URL(path, this.targetUrl);

    // Add query parameters from request.query
    Object.entries(request.query || {}).forEach(([key, value]) => {
      url.searchParams.append(key, value);
    });

    const entry: HAREntry = {
      startedDateTime: now.toISOString(),
      time: 0,
      request: {
        method: method.toUpperCase(),
        url: url.toString(),
        httpVersion: 'HTTP/1.1',
        headers: Object.entries(request.headers || {}).map(([name, value]) => ({
          name: name.toLowerCase(), // Normalize header names
          value: String(value), // Ensure value is a string
        })),
        queryString: Object.entries(request.query || {}).map(([name, value]) => ({
          name,
          value: String(value), // Ensure value is a string
        })),
        // Ensure postData is properly included for all requests with body
        postData: request.body
          ? {
              mimeType: request.contentType,
              text: typeof request.body === 'string' ? request.body : JSON.stringify(request.body),
            }
          : undefined,
      },
      response: {
        status: response.status,
        statusText: response.status === 200 ? 'OK' : 'Error',
        httpVersion: 'HTTP/1.1',
        headers: Object.entries(response.headers || {}).map(([name, value]) => ({
          name: name.toLowerCase(), // Normalize header names
          value: String(value), // Ensure value is a string
        })),
        content: {
          // If rawData is available, just store size but defer content processing
          size: response.rawData
            ? response.rawData.length
            : response.body
              ? JSON.stringify(response.body).length
              : 0,
          mimeType: response.contentType || 'application/json',
          // Use a placeholder for rawData, or convert body as before
          text: response.rawData
            ? '[Content stored but not processed for performance]'
            : typeof response.body === 'string'
              ? response.body
              : JSON.stringify(response.body),
        },
      },
    };

    this.harEntries.push(entry);
  }

  private buildQueryString(query: Record<string, string>): string {
    if (!query || Object.keys(query).length === 0) {
      return '';
    }
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => {
      params.append(key, value);
    });
    return `?${params.toString()}`;
  }

  private addSecurityScheme(security: SecurityInfo): string {
    // Use a consistent name based on the type with underscore suffix
    const schemeName = security.type === 'apiKey' ? 'apiKey_' : `${security.type}_`;
    let scheme: OpenAPIV3_1.SecuritySchemeObject;

    switch (security.type) {
      case 'apiKey':
        scheme = {
          type: 'apiKey',
          name: security.name || 'x-api-key',
          in: security.in || 'header',
        };
        break;

      case 'oauth2':
        scheme = {
          type: 'oauth2',
          flows: security.flows || {
            implicit: {
              authorizationUrl: 'https://example.com/oauth/authorize',
              scopes: {
                read: 'Read access',
                write: 'Write access',
              },
            },
          },
        };
        break;

      case 'http':
        scheme = {
          type: 'http',
          scheme: security.scheme || 'bearer',
        };
        break;

      case 'openIdConnect':
        scheme = {
          type: 'openIdConnect',
          openIdConnectUrl:
            security.openIdConnectUrl || 'https://example.com/.well-known/openid-configuration',
        };
        break;

      default:
        throw new Error(`Unsupported security type: ${security.type}`);
    }

    this.securitySchemes.set(schemeName, scheme);
    return schemeName;
  }

  public recordEndpoint(
    path: string,
    method: string,
    request: RequestInfo,
    response: ResponseInfo
  ): void {
    // Convert path parameters to OpenAPI format
    // Handles: numeric IDs, UUIDs, Plex GUIDs, and long string keys
    const openApiPath = path
      .replace(
        /\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/g,
        '/{guid}'
      )
      .replace(/\/([0-9a-zA-Z_-]{30,})/g, '/{key}')
      .replace(/\/(\d+)/g, '/{id}')
      .replace(/:(\w+)/g, '{$1}');
    const key = `${method}:${openApiPath}`;
    const endpoint: EndpointInfo = this.endpoints.get(key) || {
      path: openApiPath,
      method,
      responses: {},
      parameters: [],
      requestBody:
        method.toLowerCase() === 'get'
          ? undefined
          : {
              required: false,
              content: {},
            },
    };

    // Add security schemes if present
    if (request.security) {
      endpoint.security = request.security.map((security) => {
        const schemeName = this.addSecurityScheme(security);
        return { [schemeName]: [] }; // Empty array for scopes
      });
    }

    // Add path parameters
    const pathParams = openApiPath.match(/\{(\w+)\}/g) || [];
    pathParams.forEach((param) => {
      const paramName = param.slice(1, -1);
      if (!endpoint.parameters.some((p) => p.name === paramName)) {
        endpoint.parameters.push({
          name: paramName,
          in: 'path',
          required: true,
          schema: {
            type: 'string',
          } satisfies OpenAPIV3_1.SchemaObject,
        });
      }
    });

    // Add query parameters
    Object.entries(request.query).forEach(([key, value]) => {
      if (!endpoint.parameters.some((p) => p.name === key)) {
        endpoint.parameters.push({
          name: key,
          in: 'query',
          schema: {
            type: 'string',
          } satisfies OpenAPIV3_1.SchemaObject,
        });
      }
    });

    // Add request headers as parameters
    if (request.headers) {
      Object.entries(request.headers).forEach(([name, value]) => {
        if (!endpoint.parameters.some((p) => p.name === name)) {
          endpoint.parameters.push({
            name: name,
            in: 'header',
            required: false,
            schema: {
              type: 'string',
              example: value,
            } satisfies OpenAPIV3_1.SchemaObject,
          });
        }
      });
    }

    // Add request body schema if present and not a GET request
    if (request.body && method.toLowerCase() !== 'get') {
      const contentType = request.contentType || 'application/json';
      if (endpoint.requestBody && !endpoint.requestBody.content[contentType]) {
        const schema = this.generateJsonSchema(request.body);
        endpoint.requestBody.content[contentType] = {
          schema,
        };
      }
    }

    // Add response schema
    const responseContentType = response.contentType || 'application/json';

    // Initialize response object if it doesn't exist
    if (!endpoint.responses[response.status]) {
      endpoint.responses[response.status] = {
        description: `Response for ${method.toUpperCase()} ${path}`,
        content: {},
      };
    }

    // Ensure content object exists
    const responseObj = endpoint.responses[response.status];
    if (!responseObj.content) {
      responseObj.content = {};
    }

    // Skip schema generation if we're using rawData for deferred processing
    if (!response.rawData) {
      // Generate schema for the current response
      const currentSchema = this.generateJsonSchema(response.body);

      // Get existing schemas for this endpoint and status code
      const schemaKey = `${key}:${response.status}:${responseContentType}`;
      const existingSchemas = this.schemaCache.get(schemaKey) || [];

      // Add the current schema to the cache
      existingSchemas.push(currentSchema);
      this.schemaCache.set(schemaKey, existingSchemas);

      // Merge all schemas for this endpoint and status code
      const mergedSchema = this.deepMergeSchemas(existingSchemas);

      // Update the content with the merged schema
      responseObj.content[responseContentType] = {
        schema: mergedSchema,
      };
    } else {
      // Just create a placeholder schema when using deferred processing
      responseObj.content[responseContentType] = {
        schema: {
          type: 'object',
          description: 'Schema generation deferred to improve performance',
        },
      };

      // Store the raw data for later processing
      let pathMap = this.rawDataCache.get(path);
      if (!pathMap) {
        pathMap = new Map<string, RawResponseData>();
        this.rawDataCache.set(path, pathMap);
      }

      pathMap.set(method, {
        rawData: response.rawData ? response.rawData.toString('base64') : '',
        status: response.status,
        headers: response.headers,
      });
    }

    // Add response headers
    if (response.headers && Object.keys(response.headers).length > 0) {
      endpoint.responses[response.status].headers = Object.entries(response.headers).reduce(
        (acc, [name, value]) => {
          acc[name] = {
            schema: {
              type: 'string',
              example: value,
            },
            description: `Response header ${name}`,
          };
          return acc;
        },
        {} as NonNullable<OpenAPIV3_1.ResponseObject['headers']>
      );
    }

    this.endpoints.set(key, endpoint);

    // Record in HAR
    this.recordHAREntry(path, method, request, response);
  }

  // Process any raw data in HAR entries before returning
  private processHAREntries(): void {
    // For each HAR entry with placeholder text, process the raw data
    for (let i = 0; i < this.harEntries.length; i++) {
      const entry = this.harEntries[i];

      // Check if this entry has deferred processing
      if (entry.response.content.text === '[Content stored but not processed for performance]') {
        try {
          // Get the URL path and method
          const url = new URL(entry.request.url);
          const path = url.pathname;
          const method = entry.request.method.toLowerCase();

          // Try to get the raw data from our cache
          const pathMap = this.rawDataCache.get(path);
          if (!pathMap) continue;

          const responseData = pathMap.get(method);
          if (!responseData || !responseData.rawData) continue;

          // Get content type and encoding info
          const contentEncoding = entry.response.headers.find(
            (h) => h.name.toLowerCase() === 'content-encoding'
          )?.value;

          // Process based on content type and encoding
          let text: string;

          // Handle compressed content
          if (contentEncoding && contentEncoding.includes('gzip')) {
            const buffer = Buffer.from(responseData.rawData, 'base64');
            const gunzipped = zlib.gunzipSync(buffer);
            text = gunzipped.toString('utf-8');
          } else {
            // Handle non-compressed content
            const buffer = Buffer.from(responseData.rawData, 'base64');
            text = buffer.toString('utf-8');
          }

          // Process based on content type
          const contentType = entry.response.content.mimeType;
          if (contentType.includes('json')) {
            try {
              // First attempt standard JSON parsing
              const jsonData = JSON.parse(text);
              entry.response.content.text = JSON.stringify(jsonData);
            } catch (e) {
              // Try cleaning the JSON first
              try {
                // Clean the JSON string
                const cleanedText = this.cleanJsonString(text);
                const jsonData = JSON.parse(cleanedText);
                entry.response.content.text = JSON.stringify(jsonData);
              } catch (e2) {
                // If parsing still fails, fall back to the raw text
                entry.response.content.text = text;
              }
            }
          } else {
            // For non-JSON content, just use the text
            entry.response.content.text = text;
          }
        } catch (error) {
          entry.response.content.text = '[Error processing content]';
        }
      }
    }
  }

  // Process any raw data before generating OpenAPI specs
  private processRawData(): void {
    if (!this.rawDataCache || this.rawDataCache.size === 0) return;

    // Process each path and method in the raw data cache
    for (const [path, methodMap] of this.rawDataCache.entries()) {
      for (const [method, responseData] of methodMap.entries()) {
        const operation = this.getOperationForPathAndMethod(path, method);
        if (!operation) continue;

        const { rawData, status, headers = {} } = responseData as RawResponseData;
        if (!rawData) continue;

        // Find the response object for this status code
        const responseKey = status.toString();
        if (!operation.responses) {
          operation.responses = {};
        }
        if (!operation.responses[responseKey]) {
          operation.responses[responseKey] = {
            description: `Response for status code ${responseKey}`,
          };
        }

        const response = operation.responses[responseKey] as OpenAPIV3_1.ResponseObject;
        if (!response.content) {
          response.content = {};
        }

        // Determine content type from headers
        let contentType = 'application/json'; // Default
        const contentTypeHeader = Object.keys(headers).find(
          (key) => key.toLowerCase() === 'content-type'
        );
        if (contentTypeHeader && headers[contentTypeHeader]) {
          contentType = headers[contentTypeHeader].split(';')[0];
        }

        // Check if content is compressed
        const contentEncodingHeader = Object.keys(headers).find(
          (key) => key.toLowerCase() === 'content-encoding'
        );
        const contentEncoding = contentEncodingHeader ? headers[contentEncodingHeader] : null;

        // Process based on encoding and content type
        try {
          let text: string;

          // Handle compressed content
          if (contentEncoding && contentEncoding.includes('gzip')) {
            const buffer = Buffer.from(rawData, 'base64');
            const gunzipped = zlib.gunzipSync(buffer);
            text = gunzipped.toString('utf-8');
          } else {
            // Handle non-compressed content
            // Base64 decode if needed
            const buffer = Buffer.from(rawData, 'base64');
            text = buffer.toString('utf-8');
          }

          // Process based on content type
          if (contentType.includes('json')) {
            try {
              // First attempt standard JSON parsing
              const jsonData = JSON.parse(text);

              const schema = this.generateJsonSchema(jsonData);
              response.content[contentType] = {
                schema,
              };
            } catch (e) {
              // Try cleaning the JSON first
              try {
                // Clean the JSON string
                const cleanedText = this.cleanJsonString(text);
                const jsonData = JSON.parse(cleanedText);

                const schema = this.generateJsonSchema(jsonData);
                response.content[contentType] = {
                  schema,
                };
              } catch (e2) {
                // If parsing still fails, try to infer the schema from structure
                if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
                  // Looks like JSON-like structure, infer schema
                  const schema = this.generateSchemaFromStructure(text);
                  response.content[contentType] = {
                    schema,
                  };
                } else {
                  // Not JSON-like, treat as string
                  response.content[contentType] = {
                    schema: {
                      type: 'string',
                      description: 'Non-parseable content',
                    },
                  };
                }
              }
            }
          } else if (contentType.includes('xml')) {
            // Handle XML content
            response.content[contentType] = {
              schema: {
                type: 'string',
                format: 'xml',
                description: 'XML content',
              },
            };
          } else if (contentType.includes('image/')) {
            // Handle image content
            response.content[contentType] = {
              schema: {
                type: 'string',
                format: 'binary',
                description: 'Image content',
              },
            };
          } else {
            // Handle other content types
            response.content[contentType] = {
              schema: {
                type: 'string',
                description: text.length > 100 ? `${text.substring(0, 100)}...` : text,
              },
            };
          }
        } catch (error) {
          // Handle errors during processing
          console.error(`Error processing raw data for ${path} ${method}:`, error);
          response.content['text/plain'] = {
            schema: {
              type: 'string',
              description: 'Error processing content',
            },
          };
        }
      }
    }

    // Clear processed data
    this.rawDataCache.clear();
  }

  public getOpenAPISpec(): OpenAPIV3_1.Document {
    // Process any deferred raw data before generating the spec
    this.processRawData();

    const paths = Array.from(this.endpoints.entries()).reduce<Required<PathsObject>>(
      (acc, [key, info]) => {
        const [method, path] = key.split(':');

        if (!acc[path]) {
          acc[path] = {} as PathItemObject;
        }

        const operation: OpenAPIV3_1.OperationObject = {
          summary: `${method.toUpperCase()} ${path}`,
          responses: info.responses,
        };

        // Only include parameters if there are any
        if (info.parameters.length > 0) {
          // Filter out duplicate parameters and format them correctly
          const uniqueParams = info.parameters.reduce<OpenAPIV3_1.ParameterObject[]>(
            (params, param) => {
              const existing = params.find((p) => p.name === param.name && p.in === param.in);
              if (!existing) {
                const formattedParam: OpenAPIV3_1.ParameterObject = {
                  name: param.name,
                  in: param.in,
                  schema: {
                    type: 'string',
                  } satisfies OpenAPIV3_1.SchemaObject,
                };

                // Only add required field for path parameters
                if (param.in === 'path') {
                  formattedParam.required = true;
                }

                // Only add example for header parameters
                if (param.in === 'header' && param.schema && 'example' in param.schema) {
                  (formattedParam.schema as OpenAPIV3_1.SchemaObject).example =
                    param.schema.example;
                }

                params.push(formattedParam);
              }
              return params;
            },
            []
          );

          operation.parameters = uniqueParams;
        }

        // Only include requestBody if it exists
        if (info.requestBody) {
          operation.requestBody = info.requestBody;
        }

        // Only add security if it exists
        if (info.security) {
          operation.security = info.security;
        }

        // @ts-ignore - TypeScript index expression issue
        acc[path][method.toLowerCase() as string] = operation;
        return acc;
      },
      {}
    );

    const spec: OpenAPIV3_1.Document = {
      openapi: '3.1.0',
      info: {
        title: 'API Documentation',
        version: '1.0.0',
        description: 'Automatically generated API documentation from proxy traffic',
      },
      servers: [
        {
          url: this.targetUrl,
        },
      ],
      paths,
      components: {
        securitySchemes: Object.fromEntries(this.securitySchemes),
        schemas: {},
      },
    };

    return spec;
  }

  public getOpenAPISpecAsYAML(): string {
    const spec = this.getOpenAPISpec();
    return stringify(spec, {
      indent: 2,
      simpleKeys: true,
      aliasDuplicateObjects: false,
      strict: true,
    });
  }

  public saveOpenAPISpec(outputDir: string): void {
    const spec = this.getOpenAPISpec();
    const yamlSpec = this.getOpenAPISpecAsYAML();

    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Save JSON spec
    fs.writeFileSync(path.join(outputDir, 'openapi.json'), JSON.stringify(spec, null, 2));

    // Save YAML spec
    fs.writeFileSync(path.join(outputDir, 'openapi.yaml'), yamlSpec);
  }

  // Get operation for a path and method
  private getOperationForPathAndMethod(path: string, method: string): EndpointInfo | undefined {
    // Convert path parameters to OpenAPI format if needed
    const openApiPath = path.replace(/\/(\d+)/g, '/{id}').replace(/:(\w+)/g, '{$1}');
    const key = `${method}:${openApiPath}`;
    return this.endpoints.get(key);
  }

  public generateHAR(): any {
    // Process any raw data before generating HAR
    this.processHAREntries();

    return {
      log: {
        version: '1.2',
        creator: {
          name: 'Arbiter',
          version: '1.0.0',
        },
        entries: this.harEntries,
      },
    };
  }

  // Generate a schema by analyzing the structure of a text that might be JSON-like
  private generateSchemaFromStructure(text: string): OpenAPIV3_1.SchemaObject {
    // First, try to determine if this is an array or object
    const trimmedText = text.trim();

    if (trimmedText.startsWith('[') && trimmedText.endsWith(']')) {
      // Looks like an array
      return {
        type: 'array',
        description: 'Array-like structure detected',
        items: {
          type: 'object',
          description: 'Array items (structure inferred)',
        },
      };
    }

    if (trimmedText.startsWith('{') && trimmedText.endsWith('}')) {
      // Looks like an object - try to extract some field names
      try {
        // Extract property names using a regex that looks for different "key": patterns
        // This matcher is more flexible and can handle single quotes, double quotes, and unquoted keys
        const propMatches = trimmedText.match(/["']?([a-zA-Z0-9_$]+)["']?\s*:/g) || [];

        if (propMatches.length > 0) {
          const properties: Record<string, OpenAPIV3_1.SchemaObject> = {};

          // Extract property names and create a basic schema
          propMatches.forEach((match) => {
            // Clean up the property name by removing quotes and colon
            const propName = match.replace(/["']/g, '').replace(':', '').trim();
            if (propName && !properties[propName]) {
              // Try to guess the type based on what follows the property
              const propPattern = new RegExp(`["']?${propName}["']?\\s*:\\s*(.{1,50})`, 'g');
              const valueMatch = propPattern.exec(trimmedText);

              if (valueMatch && valueMatch[1]) {
                const valueStart = valueMatch[1].trim();

                if (valueStart.startsWith('{')) {
                  properties[propName] = {
                    type: 'object',
                    description: 'Nested object detected',
                  };
                } else if (valueStart.startsWith('[')) {
                  properties[propName] = {
                    type: 'array',
                    description: 'Array value detected',
                    items: {
                      type: 'object',
                      description: 'Array items (structure inferred)',
                    },
                  };
                } else if (valueStart.startsWith('"') || valueStart.startsWith("'")) {
                  properties[propName] = {
                    type: 'string',
                  };
                } else if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?/.test(valueStart)) {
                  properties[propName] = {
                    type: valueStart.includes('.') ? 'number' : 'integer',
                  };
                } else if (valueStart.startsWith('true') || valueStart.startsWith('false')) {
                  properties[propName] = {
                    type: 'boolean',
                  };
                } else if (valueStart.startsWith('null')) {
                  properties[propName] = {
                    type: 'null',
                  };
                } else {
                  properties[propName] = {
                    type: 'string',
                    description: 'Property detected by structure analysis',
                  };
                }
              } else {
                properties[propName] = {
                  type: 'string',
                  description: 'Property detected by structure analysis',
                };
              }
            }
          });

          return {
            type: 'object',
            properties,
            description: 'Object structure detected with properties',
          };
        }
      } catch (e) {
        // If property extraction fails, fall back to a generic object schema
      }

      // Generic object
      return {
        type: 'object',
        description: 'Object-like structure detected',
      };
    }

    // Not clearly structured as JSON
    return {
      type: 'string',
      description: 'Unstructured content',
    };
  }

  // Helper to clean up potential JSON issues
  private cleanJsonString(text: string): string {
    try {
      // Remove JavaScript-style comments
      let cleaned = text
        .replace(/\/\/.*$/gm, '') // Remove single line comments
        .replace(/\/\*[\s\S]*?\*\//g, ''); // Remove multi-line comments

      // Handle trailing commas in objects and arrays
      cleaned = cleaned.replace(/,\s*}/g, '}').replace(/,\s*\]/g, ']');

      // Fix unquoted property names (only basic cases)
      cleaned = cleaned.replace(/([{,]\s*)([a-zA-Z0-9_$]+)(\s*:)/g, '$1"$2"$3');

      // Fix single quotes used for strings (convert to double quotes)
      // This is complex - we need to avoid replacing quotes inside quotes
      let inString = false;
      let inSingleQuotedString = false;
      let result = '';

      for (let i = 0; i < cleaned.length; i++) {
        const char = cleaned[i];
        const prevChar = i > 0 ? cleaned[i - 1] : '';

        // Handle escape sequences
        if (prevChar === '\\') {
          result += char;
          continue;
        }

        if (char === '"' && !inSingleQuotedString) {
          inString = !inString;
          result += char;
        } else if (char === "'" && !inString) {
          inSingleQuotedString = !inSingleQuotedString;
          result += '"'; // Replace single quote with double quote
        } else {
          result += char;
        }
      }

      return result;
    } catch (e) {
      // If cleaning fails, return the original text
      return text;
    }
  }
}

export const openApiStore = new OpenAPIStore();

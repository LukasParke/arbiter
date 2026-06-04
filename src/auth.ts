import fs from 'fs';
import path from 'path';
import os from 'os';

export interface AuthConfig {
  type: 'plex-token' | 'bearer' | 'api-key';
  token: string;
  headerName?: string;
  queryParamName?: string;
}

const AUTH_CONFIG_DIR = path.join(os.homedir(), '.arbiter');
const AUTH_CONFIG_FILE = path.join(AUTH_CONFIG_DIR, 'auth.json');

export class AuthManager {
  private config: AuthConfig | null = null;

  constructor(config?: AuthConfig) {
    if (config) {
      this.config = config;
    } else {
      this.loadFromDisk();
    }
  }

  static fromToken(token: string, type: AuthConfig['type'] = 'plex-token'): AuthManager {
    return new AuthManager({ type, token });
  }

  private loadFromDisk(): void {
    try {
      if (fs.existsSync(AUTH_CONFIG_FILE)) {
        const raw = fs.readFileSync(AUTH_CONFIG_FILE, 'utf-8');
        this.config = JSON.parse(raw) as AuthConfig;
      }
    } catch {
      // Ignore load errors
    }
  }

  saveToDisk(): void {
    if (!this.config) {return;}
    try {
      if (!fs.existsSync(AUTH_CONFIG_DIR)) {
        fs.mkdirSync(AUTH_CONFIG_DIR, { recursive: true });
      }
      fs.writeFileSync(AUTH_CONFIG_FILE, JSON.stringify(this.config, null, 2));
    } catch {
      // Ignore save errors
    }
  }

  getHeaders(): Record<string, string> {
    if (!this.config) {return {};}

    switch (this.config.type) {
      case 'plex-token':
        return { 'X-Plex-Token': this.config.token };
      case 'bearer':
        return { Authorization: `Bearer ${this.config.token}` };
      case 'api-key':
        return { [this.config.headerName || 'X-API-Key']: this.config.token };
      default:
        return {};
    }
  }

  getQueryParams(): Record<string, string> {
    if (!this.config) {return {};}

    if (this.config.type === 'plex-token') {
      return { 'X-Plex-Token': this.config.token };
    }
    if (this.config.type === 'api-key' && this.config.queryParamName) {
      return { [this.config.queryParamName]: this.config.token };
    }
    return {};
  }

  isAuthenticated(): boolean {
    return this.config !== null && this.config.token.length > 0;
  }

  redactedToken(): string {
    if (!this.config) {return 'none';}
    const t = this.config.token;
    if (t.length <= 8) {return '***';}
    return `${t.slice(0, 4)}...${t.slice(-4)}`;
  }
}

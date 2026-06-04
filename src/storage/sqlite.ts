import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import type { StorageAdapter } from './types.js';

export class SQLiteStorage implements StorageAdapter {
  private db: Database.Database | null = null;

  async init(dbFilePath: string): Promise<void> {
    const resolvedPath = path.resolve(dbFilePath);
    const dir = path.dirname(resolvedPath);
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    } catch {}

    // Open or create database
    this.db = new Database(resolvedPath);
    this.db.pragma('journal_mode = WAL');
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS har_entries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          startedDateTime TEXT NOT NULL,
          time INTEGER NOT NULL,
          request TEXT NOT NULL,
          response TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_har_started ON har_entries(startedDateTime);

        CREATE TABLE IF NOT EXISTS endpoints (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT NOT NULL,
          method TEXT NOT NULL,
          data TEXT NOT NULL,
          UNIQUE(path, method)
        );
        CREATE INDEX IF NOT EXISTS idx_endpoints_path_method ON endpoints(path, method);
      `);
    } catch (e) {
      // If schema creation fails, close DB to avoid holding a bad handle
      try {
        this.db.close();
      } catch {}
      this.db = null;
      throw e;
    }
  }

  isReady(): boolean {
    return this.db !== null;
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async saveHarEntry(entry: any): Promise<void> {
    if (!this.db) {
      return;
    }
    try {
      const stmt = this.db.prepare(
        'INSERT INTO har_entries (startedDateTime, time, request, response) VALUES (?, ?, ?, ?)'
      );
      stmt.run(
        entry.startedDateTime,
        entry.time,
        JSON.stringify(entry.request ?? {}),
        JSON.stringify(entry.response ?? {})
      );
    } catch {}
  }

  async getHarLog(): Promise<any> {
    const empty = {
      log: { version: '1.2', creator: { name: 'Arbiter', version: '1.0.0' }, entries: [] as any[] },
    };
    if (!this.db) {
      return empty;
    }
    try {
      const rows = this.db
        .prepare('SELECT startedDateTime, time, request, response FROM har_entries ORDER BY id ASC')
        .all() as Array<{
        startedDateTime: string;
        time: number;
        request: string;
        response: string;
      }>;
      const entries = rows.map(
        (r: { startedDateTime: string; time: number; request: string; response: string }) => {
          let req: any = {};
          let res: any = {};
          try {
            req = JSON.parse(r.request);
          } catch {}
          try {
            res = JSON.parse(r.response);
          } catch {}
          return {
            startedDateTime: r.startedDateTime,
            time: r.time,
            request: req,
            response: res,
          };
        }
      );
      return { log: { ...empty.log, entries } };
    } catch {
      return empty;
    }
  }

  async clearHar(): Promise<void> {
    if (!this.db) {
      return;
    }
    try {
      this.db.prepare('DELETE FROM har_entries').run();
    } catch {}
  }

  async upsertEndpoint(pathStr: string, method: string, data: any): Promise<void> {
    if (!this.db) {
      return;
    }
    try {
      const stmt = this.db.prepare(
        `INSERT INTO endpoints (path, method, data) VALUES (?, ?, ?)
         ON CONFLICT(path, method) DO UPDATE SET data=excluded.data`
      );
      stmt.run(pathStr, method.toLowerCase(), JSON.stringify(data ?? {}));
    } catch {}
  }

  async getAllEndpoints(): Promise<Array<{ path: string; method: string; data: any }>> {
    if (!this.db) {
      return [];
    }
    try {
      const rows = this.db.prepare('SELECT path, method, data FROM endpoints').all() as Array<{
        path: string;
        method: string;
        data: string;
      }>;
      return rows.map((r: { path: string; method: string; data: string }) => {
        let data: any = {};
        try {
          data = JSON.parse(r.data);
        } catch {}
        return { path: r.path, method: r.method, data };
      });
    } catch {
      return [];
    }
  }
}

export const sqliteStorage = new SQLiteStorage();

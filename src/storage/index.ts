import { sqliteStorage } from './sqlite.js';
import type { StorageAdapter } from './types.js';

const storageInstance: StorageAdapter = sqliteStorage;

export async function initStorage(dbPath: string): Promise<StorageAdapter> {
  await storageInstance.init(dbPath);
  return storageInstance;
}

export function storage(): StorageAdapter {
  return storageInstance;
}

// @ts-nocheck
// requires: npm install better-sqlite3 @types/better-sqlite3
import Database, { type Statement } from "better-sqlite3";
import type { PatternByte, PatternCacheAdapter } from "../../src/index.js";
import { PatternScanner } from "../../src/index.js";

// better-sqlite3 is fully sync so it fits the adapter interface directly: no L1 needed
class SQLitePatternCache implements PatternCacheAdapter {
  private readonly get_stmt: Statement;
  private readonly set_stmt: Statement;

  constructor(dbPath: string) {
    const db = new Database(dbPath);
    db.exec(`CREATE TABLE IF NOT EXISTS pattern_cache (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`);
    this.get_stmt = db.prepare("SELECT value FROM pattern_cache WHERE key = ?");
    this.set_stmt = db.prepare("INSERT OR REPLACE INTO pattern_cache (key, value) VALUES (?, ?)");
  }

  get(key: string): PatternByte[] | null {
    const row = this.get_stmt.get(key) as { value: string } | undefined;
    return row ? JSON.parse(row.value) : null;
  }

  set(key: string, value: PatternByte[]): void {
    this.set_stmt.run(key, JSON.stringify(value));
  }
}

const cache = new SQLitePatternCache("./pattern-cache.db");
const data = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3]);
const scanner = new PatternScanner(data, { cache });
console.log(scanner.findPattern("55 48 89 E5")); // [0]

// @ts-nocheck
// requires: npm install ioredis
import Redis from "ioredis";
import type { PatternByte, PatternCacheAdapter } from "../../src/index.js";
import { PatternScanner } from "../../src/index.js";

// Redis is async but the adapter must be sync: local Map as L1, Redis as async write-behind.
// Call preWarm() once at startup to restore cached patterns from a previous run.
class RedisPatternCache implements PatternCacheAdapter {
  private local = new Map<string, PatternByte[]>();
  private redis: Redis;

  constructor(redisUrl: string) {
    this.redis = new Redis(redisUrl);
  }

  get(key: string): PatternByte[] | null {
    return this.local.get(key) ?? null;
  }

  set(key: string, value: PatternByte[]): void {
    this.local.set(key, value);
    this.redis.set(`sigscan:${key}`, JSON.stringify(value)).catch(() => {});
  }

  async preWarm(keys: string[]): Promise<void> {
    const values = await this.redis.mget(keys.map(k => `sigscan:${k}`));
    for (let i = 0; i < keys.length; i++) {
      if (values[i]) this.local.set(keys[i], JSON.parse(values[i]));
    }
  }
}

const cache = new RedisPatternCache("redis://localhost:6379");
await cache.preWarm(["55 48 89 E5"]);

const data = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3]);
const scanner = new PatternScanner(data, { cache });
console.log(scanner.findPattern("55 48 89 E5")); // [0]

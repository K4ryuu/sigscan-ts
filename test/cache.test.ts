import { describe, expect, it } from "bun:test";
import { LRUPatternCache, PatternScanner } from "../src/index.js";
import type { PatternByte, PatternCacheAdapter } from "../src/index.js";

const DATA = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3]);
const PATTERN = "55 48 89 E5";

describe("LRUPatternCache", () => {
  it("returns null on miss", () => {
    const cache = new LRUPatternCache();
    expect(cache.get("missing")).toBeNull();
  });

  it("returns value after set", () => {
    const cache = new LRUPatternCache();
    const value: PatternByte[] = [0x55, 0x48, null, 0xe5];
    cache.set("key", value);
    expect(cache.get("key")).toEqual(value);
  });

  it("evicts oldest entry when full", () => {
    const cache = new LRUPatternCache(2);
    cache.set("a", [0x01]);
    cache.set("b", [0x02]);
    cache.set("c", [0x03]); // evicts "a"
    expect(cache.get("a")).toBeNull();
    expect(cache.get("b")).toEqual([0x02]);
    expect(cache.get("c")).toEqual([0x03]);
  });

  it("tracks size correctly", () => {
    const cache = new LRUPatternCache(10);
    expect(cache.size).toBe(0);
    cache.set("a", [0x01]);
    cache.set("b", [0x02]);
    expect(cache.size).toBe(2);
  });

  it("size stays at maxSize after eviction", () => {
    const cache = new LRUPatternCache(2);
    cache.set("a", [0x01]);
    cache.set("b", [0x02]);
    cache.set("c", [0x03]);
    expect(cache.size).toBe(2);
  });
});

describe("PatternScanner cache integration", () => {
  it("uses default shared cache when no option given", () => {
    const scanner = new PatternScanner(DATA);
    expect(scanner.findPattern(PATTERN)).toEqual([0]);
  });

  it("cache: false disables caching, still returns correct results", () => {
    const scanner = new PatternScanner(DATA, { cache: false });
    expect(scanner.findPattern(PATTERN)).toEqual([0]);
  });

  it("custom LRU cache is used", () => {
    const cache = new LRUPatternCache(64);
    const scanner = new PatternScanner(DATA, { cache });
    scanner.findPattern(PATTERN);
    expect(cache.get(PATTERN)).not.toBeNull();
  });

  it("custom adapter get is called on repeated scan", () => {
    let getCalls = 0;
    const adapter: PatternCacheAdapter = {
      get(_key) { getCalls++; return null; },
      set() {},
    };
    const scanner = new PatternScanner(DATA, { cache: adapter });
    scanner.findPattern(PATTERN);
    scanner.findPattern(PATTERN);
    expect(getCalls).toBe(2);
  });

  it("custom adapter set is called on first parse", () => {
    let setCalls = 0;
    const stored = new Map<string, PatternByte[]>();
    const adapter: PatternCacheAdapter = {
      get: (key) => stored.get(key) ?? null,
      set(key, value) { setCalls++; stored.set(key, value); },
    };
    const scanner = new PatternScanner(DATA, { cache: adapter });
    scanner.findPattern(PATTERN);
    scanner.findPattern(PATTERN); // hit, no extra set
    expect(setCalls).toBe(1);
  });

  it("cached parse result is reused, not reparsed", () => {
    const stored = new Map<string, PatternByte[]>();
    const adapter: PatternCacheAdapter = {
      get: (key) => stored.get(key) ?? null,
      set(key, value) { stored.set(key, value); },
    };
    const scanner = new PatternScanner(DATA, { cache: adapter });
    scanner.findPattern(PATTERN);
    const cached = stored.get(PATTERN)!;
    scanner.findPattern(PATTERN);
    expect(stored.get(PATTERN)).toBe(cached); // same reference
  });
});

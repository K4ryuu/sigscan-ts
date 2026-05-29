import { describe, expect, it } from "bun:test";
import { PatternScanner, findPatterns, scanPatterns } from "../src/index.js";

const DATA = Buffer.from([
  0x55, 0x48, 0x89, 0xe5, 0x90, 0x90,  // offset 0
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,  // offset 6
  0x55, 0x48, 0x89, 0xe5, 0x00, 0x00,  // offset 12 (dup of first pattern)
]);

const scanner = new PatternScanner(DATA);

describe("findPatterns", () => {
  it("finds multiple solid patterns in one call", () => {
    const results = scanner.findPatterns({
      a: "55 48 89 E5",
      b: "DE AD BE EF",
    });
    expect(results["a"]).toEqual([0, 12]);
    expect(results["b"]).toEqual([6]);
  });

  it("finds wildcard patterns", () => {
    const results = scanner.findPatterns({
      wc: "55 48 ?? E5",
    });
    expect(results["wc"]).toEqual([0, 12]);
  });

  it("mixes solid and wildcard", () => {
    const results = scanner.findPatterns({
      solid:    "DE AD BE EF",
      wildcard: "55 48 ?? E5",
    });
    expect(results["solid"]).toEqual([6]);
    expect(results["wildcard"]).toEqual([0, 12]);
  });

  it("returns empty array for no match", () => {
    const results = scanner.findPatterns({ x: "FF FF FF FF" });
    expect(results["x"]).toEqual([]);
  });

  it("returns empty object for empty input", () => {
    expect(scanner.findPatterns({})).toEqual({});
  });

  it("respects limit option", () => {
    const results = scanner.findPatterns({ a: "55 48 89 E5" }, { limit: 1 });
    expect(results["a"]).toEqual([0]);
  });

  it("standalone findPatterns helper works", () => {
    const results = findPatterns(DATA, { b: "DE AD BE EF" });
    expect(results["b"]).toEqual([6]);
  });
});

describe("scanPatterns", () => {
  it("returns found/reliable/offsets per pattern", () => {
    const results = scanner.scanPatterns({
      unique:   "DE AD BE EF",
      multiple: "55 48 89 E5",
      missing:  "FF FF FF FF",
    });

    expect(results["unique"]).toEqual({ found: true,  offsets: [6],     reliable: true  });
    expect(results["multiple"]).toEqual({ found: true,  offsets: [0, 12], reliable: false });
    expect(results["missing"]).toEqual({ found: false, offsets: [],      reliable: false });
  });

  it("standalone scanPatterns helper works", () => {
    const results = scanPatterns(DATA, { b: "DE AD BE EF" });
    expect(results["b"]?.reliable).toBe(true);
  });
});

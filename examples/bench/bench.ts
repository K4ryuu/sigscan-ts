import { bench, run } from "mitata";
import { LRUPatternCache, PatternScanner } from "../../src/index.js";
import { SIGNATURE, generateBuffer } from "./generate-buffer.js";

const BUFFER_SIZE = 100 * 1024 * 1024; // 100 MB

console.log(`Generating ${BUFFER_SIZE / 1024 / 1024} MB buffer…`);
const { buffer } = generateBuffer(BUFFER_SIZE);

// pre-warm so JIT is settled before timing
const scanner = new PatternScanner(buffer);
const scannerNoCache = new PatternScanner(buffer, { cache: false });
const scannerBigCache = new PatternScanner(buffer, { cache: new LRUPatternCache(1024) });

const NO_WILDCARD   = "DE AD BE EF CA FE BA BE 01 02 03 04";
const WITH_WILDCARD = "DE AD ?? EF CA ?? BA BE 01 ?? 03 04"; // prefix-opt path
const FRAGMENTED    = "?? AD ?? EF ?? FE ?? BE ?? 02 ?? 04"; // linear fallback

// baseline: dumb JS loop, no indexOf, no cache
bench("baseline: naive JS loop", () => {
  const len = SIGNATURE.length;
  const matches: number[] = [];
  for (let i = 0; i <= buffer.length - len; i++) {
    let ok = true;
    for (let j = 0; j < len; j++) {
      if (buffer[i + j] !== SIGNATURE[j]) { ok = false; break; }
    }
    if (ok) matches.push(i);
  }
  return matches;
});

// no wildcards: straight to native indexOf
bench("findPattern: no wildcards", () => scanner.findPattern(NO_WILDCARD));
bench("findPattern: no wildcards, cache off", () => scannerNoCache.findPattern(NO_WILDCARD));

// wildcards: anchor on longest solid run, verify around it
bench("findPattern: wildcards (prefix-opt)", () => scanner.findPattern(WITH_WILDCARD));

// fully fragmented: no anchor possible, linear scan
bench("findPattern: fragmented wildcards", () => scanner.findPattern(FRAGMENTED));

// scan() wrapper with fast:true, stops after 2 hits
bench("scan() fast:true", () => scanner.scan(NO_WILDCARD, { fast: true }));

// cache size comparison
bench("cache: LRU(256) default", () => scanner.findPattern(NO_WILDCARD));
bench("cache: LRU(1024) custom", () => scannerBigCache.findPattern(NO_WILDCARD));

await run();

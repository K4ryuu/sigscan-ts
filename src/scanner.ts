import { parsePattern } from "./parser.js";
import type { PatternByte, PatternCacheAdapter, ScanOptions, ScanResult } from "./types.js";

/**
 * Built-in LRU cache for parsed patterns. Evicts the oldest entry when full
 * (insertion-order Map eviction: O(1)).
 *
 * Used as the default cache inside {@link PatternScanner}. Export it if you
 * need a custom size:
 *
 * @example
 * const scanner = new PatternScanner(data, { cache: new LRUPatternCache(512) });
 */
export class LRUPatternCache implements PatternCacheAdapter {
  private readonly store = new Map<string, PatternByte[]>();

  constructor(private readonly maxSize: number = 256) {}

  get(key: string): PatternByte[] | null {
    return this.store.get(key) ?? null;
  }

  set(key: string, value: PatternByte[]): void {
    if (this.store.size >= this.maxSize) {
      this.store.delete(this.store.keys().next().value!);
    }
    this.store.set(key, value);
  }

  get size(): number {
    return this.store.size;
  }
}

const DEFAULT_CACHE = new LRUPatternCache(256);

/**
 * High-performance signature pattern scanner for binary files.
 * Works seamlessly in Node.js, Bun, and the browser.
 */
export interface PatternScannerOptions {
  /**
   * Custom cache adapter for parsed patterns.
   * Pass `false` to disable caching entirely.
   * @default LRUPatternCache (256 slots, shared across all scanner instances)
   */
  cache?: PatternCacheAdapter | false;
}

export class PatternScanner {
  protected readonly data: Uint8Array;
  protected readonly isBuffer: boolean;
  private readonly cache: PatternCacheAdapter | null;

  /**
   * Creates a new PatternScanner instance.
   * @param data The binary data to scan (Buffer or Uint8Array).
   * @param options Optional configuration.
   */
  constructor(data: Uint8Array | Buffer, options: PatternScannerOptions = {}) {
    if (!data || (!(data instanceof Uint8Array) && !(typeof Buffer !== "undefined" && Buffer.isBuffer(data)))) {
      throw new Error("PatternScanner: data argument must be a Buffer or Uint8Array");
    }

    this.cache = options.cache === false ? null : (options.cache ?? DEFAULT_CACHE);

    // wrap Uint8Array as Buffer in Node/Bun so indexOf runs at native C++ speed
    if (typeof Buffer !== "undefined") {
      this.data = Buffer.isBuffer(data) ? data : Buffer.from(data.buffer || data, (data as any).byteOffset || 0, (data as any).byteLength || data.length);
      this.isBuffer = true;
    } else {
      this.data = data;
      this.isBuffer = false;
    }
  }

  private getCachedPattern(pattern: string): PatternByte[] {
    const hit = this.cache?.get(pattern);
    if (hit) return hit;
    const parsed = parsePattern(pattern);
    this.cache?.set(pattern, parsed);
    return parsed;
  }

  /**
   * Scans the binary for a specific signature pattern.
   *
   * Internally uses one of three search strategies depending on the pattern:
   * 1. **No wildcards**: delegates to native `Buffer.indexOf` (C++ speed).
   * 2. **Wildcards with a contiguous block ≥3 bytes**: prefix-optimization: finds
   *    the longest solid block via `indexOf`, then verifies the full pattern around it.
   * 3. **Highly fragmented wildcards**: linear byte-by-byte scan (fallback).
   *
   * @param pattern Signature string (e.g. `"55 48 89 E5"`) or pre-parsed `PatternByte[]`.
   * @param options Search options.
   * @returns Array of byte offsets where matches were found.
   *
   * @example
   * const scanner = new PatternScanner(buffer);
   * const offsets = scanner.findPattern("55 48 89 E5 ?? ?? 48 83 EC 28");
   * console.log(offsets); // [0x1000, 0x2400]
   */
  findPattern(pattern: string | PatternByte[], options: ScanOptions = {}): number[] {
    if (typeof pattern !== "string" && !Array.isArray(pattern)) {
      throw new Error("PatternScanner: pattern argument must be a string or PatternByte array");
    }
    const parsed = typeof pattern === "string" ? this.getCachedPattern(pattern) : pattern;
    if (parsed.length === 0) return [];

    const limit = options.fast ? 2 : (options.limit ?? 0);
    const startOffset = Math.max(0, options.startOffset ?? 0);
    const dataLength = this.data.length;
    const patternLength = parsed.length;

    if (startOffset + patternLength > dataLength) return [];

    const matches: number[] = [];
    const hasWildcard = parsed.some((b: PatternByte) => b === null);

    // path 1: no wildcards: hand off to native indexOf, runs at C++ speed
    if (!hasWildcard) {
      const targetBytes = new Uint8Array(parsed as number[]);

      if (this.isBuffer) {
        const buf = this.data as Buffer;
        const targetBuf = Buffer.from(targetBytes.buffer, targetBytes.byteOffset, targetBytes.byteLength);
        let offset = startOffset;
        while (offset <= dataLength - patternLength) {
          const found = buf.indexOf(targetBuf, offset);
          if (found === -1) break;
          matches.push(found);
          if (limit > 0 && matches.length >= limit) return matches;
          offset = found + 1;
        }
        return matches;
      } else {
        // browser fallback: no Buffer, manual loop
        let offset = startOffset;
        while (offset <= dataLength - patternLength) {
          let found = true;
          for (let i = 0; i < patternLength; i++) {
            if (this.data[offset + i] !== targetBytes[i]) {
              found = false;
              break;
            }
          }
          if (found) {
            matches.push(offset);
            if (limit > 0 && matches.length >= limit) return matches;
          }
          offset++;
        }
        return matches;
      }
    }

    // path 2: wildcards: find longest solid byte run, indexOf on that, verify around it
    let bestSeqOffset = -1;
    let bestSeqLength = 0;
    let currentSeqOffset = -1;
    let currentSeqLength = 0;

    for (let i = 0; i < patternLength; i++) {
      if (parsed[i] !== null) {
        if (currentSeqLength === 0) currentSeqOffset = i;
        currentSeqLength++;
      } else {
        if (currentSeqLength > bestSeqLength) {
          bestSeqLength = currentSeqLength;
          bestSeqOffset = currentSeqOffset;
        }
        currentSeqLength = 0;
      }
    }
    if (currentSeqLength > bestSeqLength) {
      bestSeqLength = currentSeqLength;
      bestSeqOffset = currentSeqOffset;
    }

    // solid run must be ≥3 bytes to be worth using as an indexOf anchor
    if (bestSeqLength >= 3 && bestSeqOffset !== -1) {
      const seqBytes = new Uint8Array(parsed.slice(bestSeqOffset, bestSeqOffset + bestSeqLength) as number[]);
      let offset = startOffset;

      if (this.isBuffer) {
        const buf = this.data as Buffer;
        const seqBuf = Buffer.from(seqBytes.buffer, seqBytes.byteOffset, seqBytes.byteLength);

        while (offset <= dataLength - patternLength) {
          const searchOffset = Math.max(offset + bestSeqOffset, startOffset);
          const found = buf.indexOf(seqBuf, searchOffset);
          if (found === -1 || found - bestSeqOffset > dataLength - patternLength) break;

          const candidateStart = found - bestSeqOffset;

          let match = true;
          for (let j = 0; j < patternLength; j++) {
            const patternByte = parsed[j];
            if (patternByte !== null && this.data[candidateStart + j] !== patternByte) {
              match = false;
              break;
            }
          }

          if (match) {
            matches.push(candidateStart);
            if (limit > 0 && matches.length >= limit) return matches;
          }
          offset = candidateStart + 1;
        }
        return matches;
      } else {
        // browser fallback
        while (offset <= dataLength - patternLength) {
          let matchSeq = true;
          for (let i = 0; i < bestSeqLength; i++) {
            if (this.data[offset + bestSeqOffset + i] !== seqBytes[i]) {
              matchSeq = false;
              break;
            }
          }

          if (matchSeq) {
            let match = true;
            for (let j = 0; j < patternLength; j++) {
              const patternByte = parsed[j];
              if (patternByte !== null && this.data[offset + j] !== patternByte) {
                match = false;
                break;
              }
            }
            if (match) {
              matches.push(offset);
              if (limit > 0 && matches.length >= limit) return matches;
            }
          }
          offset++;
        }
        return matches;
      }
    }

    // path 3: too fragmented for an anchor, full linear scan
    for (let i = startOffset; i <= dataLength - patternLength; i++) {
      let match = true;
      for (let j = 0; j < patternLength; j++) {
        const patternByte = parsed[j];
        if (patternByte !== null && this.data[i + j] !== patternByte) {
          match = false;
          break;
        }
      }
      if (match) {
        matches.push(i);
        if (limit > 0 && matches.length >= limit) return matches;
      }
    }

    return matches;
  }

  /**
   * Scans the binary for a pattern and returns a detailed {@link ScanResult}.
   *
   * @param pattern Signature string or pre-parsed `PatternByte[]`.
   * @param options Search options.
   * @returns Detailed result with `found`, `offsets`, and `reliable` fields.
   *
   * @example
   * const scanner = new PatternScanner(buffer);
   * const result = scanner.scan("55 48 89 E5", { fast: true });
   * if (result.found && result.reliable) {
   *   applyPatch(buffer, result.offsets[0]);
   * }
   */
  scan(pattern: string | PatternByte[], options: ScanOptions = {}): ScanResult {
    const requestedLimit = options.limit ?? 0;
    const probeLimit = options.fast ? 2 : requestedLimit > 0 ? Math.max(requestedLimit, 2) : 0;
    const probeOffsets = this.findPattern(pattern, options.fast ? { ...options, limit: probeLimit, fast: true } : { ...options, limit: probeLimit });
    const offsets = requestedLimit > 0 ? probeOffsets.slice(0, requestedLimit) : probeOffsets;
    return {
      found: offsets.length > 0,
      offsets,
      reliable: probeOffsets.length === 1
    };
  }
}

/**
 * Convenient single-use pattern scan helper. Creates a temporary {@link PatternScanner}
 * and runs {@link PatternScanner.scan}. Prefer the class API when scanning the same
 * buffer multiple times.
 *
 * @param data Binary buffer or `Uint8Array`.
 * @param pattern Signature string or pre-parsed `PatternByte[]`.
 * @param options Scan options.
 * @returns Detailed result with `found`, `offsets`, and `reliable` fields.
 *
 * @example
 * import { scan } from "sigscan-ts";
 * const result = scan(fs.readFileSync("game.exe"), "55 48 89 E5 ?? ?? 48 83 EC 28");
 * console.log(result.offsets); // [0x1000]
 */
export function scan(data: Uint8Array | Buffer, pattern: string | PatternByte[], options: ScanOptions = {}): ScanResult {
  const scanner = new PatternScanner(data);
  return scanner.scan(pattern, options);
}

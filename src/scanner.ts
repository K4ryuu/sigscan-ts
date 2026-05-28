import { parsePattern } from "./parser.js";
import type { PatternByte, ScanOptions, ScanResult } from "./types.js";

/**
 * High-performance signature pattern scanner for binary files.
 * Works seamlessly in Node.js, Bun, and the browser.
 */
export class PatternScanner {
  protected readonly data: Uint8Array;
  protected readonly isBuffer: boolean;

  /**
   * Creates a new PatternScanner instance.
   * @param data The binary data to scan (Buffer or Uint8Array).
   */
  constructor(data: Uint8Array | Buffer) {
    if (!data || (!(data instanceof Uint8Array) && !(typeof Buffer !== "undefined" && Buffer.isBuffer(data)))) {
      throw new Error("PatternScanner: data argument must be a Buffer or Uint8Array");
    }

    // If we are in Node.js/Bun, wrap any Uint8Array as a Buffer instantly.
    // This allows us to use native C++ speed for buffer searches (indexOf) with zero overhead.
    if (typeof Buffer !== "undefined") {
      this.data = Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer || data, (data as any).byteOffset || 0, (data as any).byteLength || data.length);
      this.isBuffer = true;
    } else {
      this.data = data;
      this.isBuffer = false;
    }
  }

  /**
   * Scans the binary for a specific signature pattern.
   *
   * @param pattern Signature string (e.g. "55 48 89 E5") or pre-parsed PatternByte array.
   * @param options Search options.
   * @returns Array of byte offsets where matches were found.
   */
  findPattern(pattern: string | PatternByte[], options: ScanOptions = {}): number[] {
    if (typeof pattern !== "string" && !Array.isArray(pattern)) {
      throw new Error("PatternScanner: pattern argument must be a string or PatternByte array");
    }
    const parsed = typeof pattern === "string" ? parsePattern(pattern) : pattern;
    if (parsed.length === 0) return [];

    const limit = options.limit ?? 0;
    const startOffset = Math.max(0, options.startOffset ?? 0);
    const dataLength = this.data.length;
    const patternLength = parsed.length;

    if (startOffset + patternLength > dataLength) return [];

    const matches: number[] = [];
    const hasWildcard = parsed.some((b) => b === null);

    // =========================================================================
    // OPTIMIZATION 1: No Wildcards (Native Fast-Path)
    // =========================================================================
    // If there are no wildcards, we can let Node/Bun's C++ indexOf engine
    // handle the search. This runs at compiled hardware speed.
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
        // Fallback for browser environment without Buffer support
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

    // =========================================================================
    // OPTIMIZATION 2: Longest Continuous Sub-Sequence Search
    // =========================================================================
    // If there are wildcards, we find the longest contiguous block of bytes in the pattern.
    // We search for this block using fast native search, and then verify the full pattern
    // around it. This is much faster than checking byte-by-byte in JS!
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

    // Use sub-sequence index searching if the block is at least 3 bytes long
    if (bestSeqLength >= 3 && bestSeqOffset !== -1) {
      const seqBytes = new Uint8Array(parsed.slice(bestSeqOffset, bestSeqOffset + bestSeqLength) as number[]);
      let offset = startOffset;

      if (this.isBuffer) {
        const buf = this.data as Buffer;
        const seqBuf = Buffer.from(seqBytes.buffer, seqBytes.byteOffset, seqBytes.byteLength);

        while (offset <= dataLength - patternLength) {
          // Adjust search offset so the native search lines up inside the pattern boundaries
          const searchOffset = Math.max(offset + bestSeqOffset, startOffset);
          const found = buf.indexOf(seqBuf, searchOffset);
          if (found === -1 || found - bestSeqOffset > dataLength - patternLength) break;

          const candidateStart = found - bestSeqOffset;

          // Verify the remaining bytes (including wildcards)
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
        // Fallback for browsers
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

    // =========================================================================
    // FALLBACK: Linear Scan
    // =========================================================================
    // Only used for highly fragmented patterns (e.g. "?? 01 ?? 02 ??")
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
   * Scans the binary for a pattern and returns a detailed ScanResult.
   *
   * @param pattern Signature string or pre-parsed PatternByte array.
   * @param options Search options.
   * @returns Detailed ScanResult object.
   */
  scan(pattern: string | PatternByte[], options: ScanOptions = {}): ScanResult {
    const offsets = this.findPattern(pattern, options);
    return {
      found: offsets.length > 0,
      offsets,
      reliable: offsets.length === 1,
    };
  }
}

/**
 * Convenient single-use pattern scan helper.
 *
 * @param data Binary buffer or Uint8Array.
 * @param pattern Signature string or pre-parsed array.
 * @param options Scan options.
 */
export function scan(
  data: Uint8Array | Buffer,
  pattern: string | PatternByte[],
  options: ScanOptions = {}
): ScanResult {
  const scanner = new PatternScanner(data);
  return scanner.scan(pattern, options);
}

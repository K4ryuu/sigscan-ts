import { PatternScanner } from "./scanner.js";
import type { StringDumpEntry, StringReference } from "./types.js";

/**
 * Advanced binary analysis engine that extends the PatternScanner.
 * Adds reverse engineering helper functions like string searches,
 * reference tracing, and automatic signature generation.
 */
export class BinaryAnalyzer extends PatternScanner {
  /**
   * Finds the byte offset of a specific string literal in the binary.
   *
   * @param str The UTF-8 string to locate.
   * @returns The file offset index if found, otherwise null.
   */
  findString(str: string): number | null {
    if (!this.isBuffer) {
      throw new Error("String scanning utilities require a Node.js/Bun Buffer environment.");
    }
    const bytes = Buffer.from(str, "utf8");
    const buf = this.data as Buffer;
    const offset = buf.indexOf(bytes);
    return offset === -1 ? null : offset;
  }

  /**
   * Extracts all printable ASCII/UTF-8 strings from the binary file (similar to the Unix `strings` command).
   * Useful for auditing, metadata inspection, and finding interesting debug keys.
   *
   * @param options Extraction options.
   * @returns List of dumped strings and their byte offsets.
   */
  dumpStrings(options: { minLength?: number } = {}): StringDumpEntry[] {
    if (!this.isBuffer) {
      throw new Error("String scanning utilities require a Node.js/Bun Buffer environment.");
    }
    const minLength = options.minLength ?? 4;
    const buf = this.data as Buffer;
    const results: StringDumpEntry[] = [];
    let start = -1;

    for (let i = 0; i < buf.length; i++) {
      const char = buf[i]!;
      // Printable ASCII characters are 32 (space) to 126 (tilde), plus common whitespace characters
      const isPrintable = (char >= 32 && char <= 126) || char === 9 || char === 10 || char === 13;

      if (isPrintable) {
        if (start === -1) start = i;
      } else {
        if (start !== -1) {
          const length = i - start;
          if (length >= minLength) {
            const text = buf.subarray(start, i).toString("utf8");
            results.push({ offset: start, text });
          }
          start = -1;
        }
      }
    }

    // Collect any remaining string at the end of the file
    if (start !== -1) {
      const length = buf.length - start;
      if (length >= minLength) {
        const text = buf.subarray(start).toString("utf8");
        results.push({ offset: start, text });
      }
    }

    return results;
  }

  /**
   * Scans the code segment for instructions referencing a target memory address (e.g. string offset)
   * using x86_64 RIP-relative addressing.
   *
   * Formula: [Instruction Address] + [Displacement Offset (4 bytes)] + [Displacement Value] = [Target Address]
   *
   * @param targetOffset The target address/offset in the binary to search references for.
   * @returns Array of found references with instruction and displacement metadata.
   */
  findStringReferences(targetOffset: number): StringReference[] {
    if (!this.isBuffer) {
      throw new Error("String scanning utilities require a Node.js/Bun Buffer environment.");
    }
    const refs: StringReference[] = [];
    const buf = this.data as Buffer;

    // Scan for any 4-byte little-endian displacement D at position p such that p + 4 + D = targetOffset
    for (let p = 0; p <= buf.length - 4; p++) {
      const displacement = buf.readInt32LE(p);
      if (p + 4 + displacement === targetOffset) {
        if (p >= 3) {
          const opcode = buf[p - 2];
          const rexPrefix = buf[p - 3];
          const isRex = rexPrefix === 0x48 || rexPrefix === 0x4C;
          
          // Estimate start of instruction (e.g., 48 8d 3d [disp] -> REX + LEA + ModRM)
          const instructionOffset = isRex ? p - 3 : (opcode === 0x8D || opcode === 0x8B ? p - 2 : p - 3);

          refs.push({
            instructionOffset,
            displacementOffset: p
          });
        }
      }
    }
    return refs;
  }

  /**
   * Traces backwards from a given instruction pointer to locate the nearest function prologue (start of function).
   *
   * Supports:
   * - GCC/Linux: `push rbp; mov rbp, rsp` (55 48 89 e5) or `push rbp; sub rsp, imm` (55 48 81 ec)
   * - MSVC/Windows: `sub rsp, imm` (48 83 ec) or `push rbx` (40 53)
   *
   * @param offset The starting position to trace back from.
   * @param maxSearchBytes Maximum distance in bytes to scan backwards.
   * @returns The file offset of the function start, or null if not found.
   */
  findFunctionStart(offset: number, maxSearchBytes = 1000): number | null {
    if (!this.isBuffer) {
      throw new Error("String scanning utilities require a Node.js/Bun Buffer environment.");
    }
    const buf = this.data as Buffer;
    const start = Math.max(0, offset - maxSearchBytes);

    for (let i = offset; i >= start; i--) {
      // 1. GCC/Linux x64: push rbp; mov rbp, rsp (55 48 89 E5)
      if (i <= buf.length - 4 && buf[i] === 0x55 && buf[i + 1] === 0x48 && buf[i + 2] === 0x89 && buf[i + 3] === 0xE5) {
        return i;
      }
      // 2. Windows/MSVC/GCC: sub rsp, imm8 (48 83 EC)
      if (i <= buf.length - 3 && buf[i] === 0x48 && buf[i + 1] === 0x83 && buf[i + 2] === 0xEC) {
        return i;
      }
      // 3. MSVC/Windows x64: push rbx (40 53)
      if (i <= buf.length - 2 && buf[i] === 0x40 && buf[i + 1] === 0x53) {
        return i;
      }
      // 4. GCC: push rbp; sub rsp, imm32 (55 48 81 EC)
      if (i <= buf.length - 4 && buf[i] === 0x55 && buf[i + 1] === 0x48 && buf[i + 2] === 0x81 && buf[i + 3] === 0xEC) {
        return i;
      }
    }
    return null;
  }

  /**
   * Automatically generates an IDA-style signature for the function containing a specific string literal.
   *
   * It works by finding the string's offset, tracing instructions that reference it, locating the containing
   * function prologue, and replacing the displacement bytes with wildcards to make the signature relocatable.
   *
   * @param str The string referenced by the target function.
   * @param length The length of the signature to extract (default: 24 bytes).
   * @returns Object containing the generated signature and the function's start address, or null.
   */
  generateSignatureFromString(str: string, length = 24): { signature: string; offset: number } | null {
    const stringOffset = this.findString(str);
    if (stringOffset === null) return null;

    const refs = this.findStringReferences(stringOffset);
    if (refs.length === 0) return null;

    // Default to the first found reference
    const ref = refs[0]!;
    const funcStart = this.findFunctionStart(ref.instructionOffset);
    if (funcStart === null) return null;

    const buf = this.data as Buffer;
    const bytes = buf.subarray(funcStart, funcStart + length);
    const patternBytes: string[] = [];

    const dispStart = ref.displacementOffset - funcStart;
    const dispEnd = dispStart + 4;

    for (let i = 0; i < bytes.length; i++) {
      // Replace dynamic displacement bytes with wildcards to keep the signature robust across game patches.
      if (i >= dispStart && i < dispEnd) {
        patternBytes.push("??");
      } else {
        patternBytes.push(bytes[i]!.toString(16).toUpperCase().padStart(2, "0"));
      }
    }

    return {
      signature: patternBytes.join(" "),
      offset: funcStart
    };
  }
}

import { PatternByte } from "./types.js";

/**
 * Parses hex signature patterns from various debuggers (IDA Pro, x64dbg, Cheat Engine)
 * into a clean array of bytes and wildcards.
 *
 * Supported formats:
 * - IDA Pro:   "48 8B C4 ?? 53" or "48 8b c4 ? 53"
 * - x64dbg:    "48.8B.C4.??.53"
 * - Cheat Eng: "48 8b c4 ?? 53"
 * - Raw hex:   "488bc4??53" (splits automatically into 2-char tokens)
 * - Escaped:   "\x48 \x8B \xC4 ? \x53"
 *
 * @param pattern The signature string to parse.
 * @returns A parsed array: byte values `0-255` for concrete bytes, `null` for wildcards.
 * @throws If the pattern contains invalid tokens.
 *
 * @example
 * parsePattern("48 8B C4 ?? 53");
 * // → [0x48, 0x8B, 0xC4, null, 0x53]
 *
 * parsePattern("48.8B.C4.??.53"); // x64dbg dot-separated
 * // → [0x48, 0x8B, 0xC4, null, 0x53]
 *
 * parsePattern("488BC4??53"); // raw hex, no spaces
 * // → [0x48, 0x8B, 0xC4, null, 0x53]
 */
export function parsePattern(pattern: string): PatternByte[] {
  if (typeof pattern !== "string") {
    throw new Error("parsePattern: pattern argument must be a string");
  }
  if (!pattern) return [];

  // 1. Standardize formatting by replacing common separators with spaces
  let normalized = pattern
    .replace(/\./g, " ") // Replace x64dbg dots
    .replace(/,/g, " ") // Replace C-style commas
    .replace(/[\[\]\{\}]/g, " ") // Strip brackets: [ ], { }
    .replace(/0x/gi, " ") // Strip 0x hex prefixes
    .replace(/\\x/g, " ") // Strip C-style hex escape prefix
    .replace(/\\\\/g, " ") // Clean up backslashes
    .trim();

  // 2. If the user pasted a raw string without spaces, split it into 2-character chunks.
  // This makes pasting raw hex dumps directly from Cheat Engine/IDA super easy!
  if (!normalized.includes(" ") && normalized.length > 2) {
    const chunks: string[] = [];
    for (let i = 0; i < normalized.length; i += 2) {
      chunks.push(normalized.substring(i, i + 2));
    }
    normalized = chunks.join(" ");
  }

  const tokens = normalized.split(/\s+/);
  const result: PatternByte[] = [];

  for (const token of tokens) {
    // Both '?' and '??' are accepted as wildcards (null)
    if (token === "?" || token === "??") {
      result.push(null);
    } else if (/^[0-9A-Fa-f]{1,2}$/.test(token)) {
      result.push(parseInt(token, 16));
    } else {
      throw new Error(`Invalid token in signature pattern: '${token}'. Must be a valid hex byte or wildcard.`);
    }
  }

  return result;
}

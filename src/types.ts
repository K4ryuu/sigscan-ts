export type PatternByte = number | null;

export interface ScanOptions {
  /**
   * Maximum number of matches to find.
   * Set to 0 to return all matches.
   * @default 0
   */
  limit?: number;
  /**
   * The byte offset in the buffer to start searching from.
   * @default 0
   */
  startOffset?: number;
}

export interface ScanResult {
  /**
   * True if at least one match was found in the binary.
   */
  found: boolean;
  /**
   * The array of byte offsets where matches were located.
   */
  offsets: number[];
  /**
   * True if exactly one match was found. Useful for verifying signature uniqueness.
   */
  reliable: boolean;
}

export interface StringDumpEntry {
  /**
   * The byte offset of the string inside the binary file.
   */
  offset: number;
  /**
   * The text representation of the string.
   */
  text: string;
}

export interface StringReference {
  /**
   * Estimated byte offset where the x64 instruction starts (e.g. LEA instruction).
   */
  instructionOffset: number;
  /**
   * Byte offset of the 4-byte displacement/offset value inside the instruction.
   */
  displacementOffset: number;
}

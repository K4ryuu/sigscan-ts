export type PatternByte = number | null;

export interface ScanOptions {
  /**
   * Maximum number of matches to find.
   * Set to 0 to return all matches.
   * @default 0
   */
  limit?: number;
  /**
   * Stop once a second match is confirmed instead of counting all matches.
   * Useful when you only need to know whether a pattern is unique.
   * @default false
   */
  fast?: boolean;
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

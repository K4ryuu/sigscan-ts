export type PatternByte = number | null;

/**
 * Pluggable cache adapter for parsed pattern results.
 *
 * Implement this interface to use a custom backing store (Redis, SQLite, etc.).
 * The default implementation is {@link LRUPatternCache} with 256 slots.
 *
 * Pass `false` to the `PatternScanner` constructor to disable caching entirely.
 *
 * @example
 * // Redis-backed adapter (example)
 * class RedisPatternCache implements PatternCacheAdapter {
 *   get(key: string) { return redisClient.get(key); }
 *   set(key: string, value: PatternByte[]) { redisClient.set(key, value); }
 * }
 */
export interface PatternCacheAdapter {
  get(key: string): PatternByte[] | null;
  set(key: string, value: PatternByte[]): void;
}

export interface ScanOptions {
  /**
   * Maximum number of matches to find.
   * Set to 0 to return all matches.
   * @default 0
   */
  limit?: number;
  /**
   * Probe up to 2 matches then stop, instead of scanning the entire buffer.
   * Useful when you only need to know whether a pattern is unique.
   *
   * `reliable` in the result is still correct when `fast: true`:
   * the scanner finds a maximum of 2 matches (probeLimit=2), so if 2 are found
   * `reliable` is set to `false` as expected. Only the full match count is skipped.
   *
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
   * The byte offsets where matches were located.
   */
  offsets: number[];
  /**
   * True if exactly one match was found anywhere in the buffer.
   * Use this to confirm the pattern is a unique signature before relying on it.
   *
   * When `fast: true` is passed, this is still correct: the scanner probes up to 2
   * matches, so any case with ≥2 matches sets this to `false` as expected.
   */
  reliable: boolean;
}

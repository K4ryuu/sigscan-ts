export type { PatternByte, PatternCacheAdapter, ScanOptions, ScanResult } from "./types.js";

export { parsePattern } from "./parser.js";

export { LRUPatternCache, PatternScanner, findPatterns, scan, scanPatterns } from "./scanner.js";
export type { PatternScannerOptions } from "./scanner.js";

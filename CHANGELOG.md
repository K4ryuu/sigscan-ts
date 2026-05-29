# Changelog

All notable changes to this project will be documented here.

---

## 1.1.0 - 2026-05-29

### Added

- **Pluggable cache adapter** — `PatternCacheAdapter` interface + `LRUPatternCache` class (default, 256 slots). Pass a custom adapter or `false` to disable. See `examples/cache/` for memory, Redis, and SQLite examples.
- **`findPatterns(patterns, options?)`** — scan multiple named patterns in one call, returns `Record<string, number[]>`. Available as a method on `PatternScanner` and as a standalone function.
- **`scanPatterns(patterns, options?)`** — same but returns `Record<string, ScanResult>` with `found`/`reliable` per pattern. Designed for gamedata.json batch verification use cases.
- **Benchmark suite** — `bun run bench` (mitata, 100 MB buffer, all scan paths + multi-pattern).

### Changed

- `PatternScanner` constructor accepts optional `PatternScannerOptions` (`{ cache? }`). Fully backwards compatible.
- CLI gamedata scan uses `scanPatterns` per binary internally.

### Performance

- **Fragmented wildcard patterns** (`?? AB ?? CD ??`): **310 ms → 12.7 ms** (~24x) — indexOf anchor threshold lowered from 3 bytes to 1.
- **Secondary filter byte** added after indexOf hit to reduce full verification calls.

---

## 1.0.1 - 2026-05-28

- Version bump, badge and metadata updates.

## 1.0.0 - 2026-05-28

### Added

- Initial release.
- High-performance pattern scanner with hybrid prefix indexOf search acceleration.
- Spaced/unspaced, dots, raw hex, and C-array signature parser.
- CLI for single pattern searches and batch gamedata.json scanning.
- Multi-library and multi-platform support in CLI gamedata check.
- Fully typed ESM and CommonJS hybrid bundle.

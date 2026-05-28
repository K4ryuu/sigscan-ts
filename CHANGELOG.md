# Changelog

All notable changes to this project will be documented here.

---

## 1.0.0 - 2026-05-28

### Added

- Initial release.
- High-performance pattern scanner with hybrid prefix indexOf search acceleration.
- Static analyzer for string literal identification, RIP-relative tracing, and automatic relocatable function signature generation.
- Spaced/unspaced, dots, raw hex, and C-array signature parser.
- Command-line interface (CLI) for single pattern searches, signature creation, and batch gamedata.json scanning.
- Dynamic multi-library and multi-platform support to the CLI `--gamedata` check (`server`, `engine2`, `client`, `tier0` library mappings).
- On-demand binary loading and caching inside CLI scan queue.
- Windows-specific MSVC function prologue tracing support (`40 53` for push rbx and `48 83 ec` for sub rsp, imm).
- End of buffer string extraction without padding/null-terminators.
- CLI integration/subprocess testing suite with near 100% test coverage.
- Fully typed ESM and CommonJS hybrid bundle distribution compilation.

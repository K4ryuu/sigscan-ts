#!/usr/bin/env node

import { readFileSync, existsSync, statSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { PatternScanner } from "./index.js";

function getPackageVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    let packagePath = join(__dirname, "../package.json");
    if (!existsSync(packagePath)) {
      packagePath = join(__dirname, "../../package.json");
    }
    if (existsSync(packagePath)) {
      const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
      return pkg.version || "1.0.0";
    }
  } catch {}
  return "1.0.0";
}

function printHelp() {
  console.log(`
\x1b[36msigscan-ts CLI\x1b[0m - High-performance binary signature scanner and analyzer

\x1b[1mUsage:\x1b[0m
  sigscan-ts --binary <file> --pattern "<signature>"
  sigscan-ts -b <file1> -b <file2> -g <gamedata.json> [options]

\x1b[1mOptions:\x1b[0m
  -b, --binary <path>    Path to file or directory (can specify multiple times, e.g. -b file1 -b file2)
  -p, --pattern <sig>    IDA, x64dbg, or Cheat Engine style byte pattern to scan for
  -g, --gamedata <file>  Path to a gamedata JSON file to batch-verify signatures
  --fast                 Stop pattern scans after confirming a second match
  --platform <type>      Target platform: "linux" or "windows" (automatically detected by default)
  -l, --limit <num>      Max matches to find (default: 0 = unlimited)
  -o, --offset <num>     Byte offset to start scanning from (default: 0)
  -v, --version          Show version number
  -h, --help             Show this help menu

\x1b[1mExamples:\x1b[0m
  sigscan-ts -b server.dll -p "48 8B C4 ?? 53"
  sigscan-ts -b libserver.so -s "Host_Say" --sig-len 32
  sigscan-ts -b libserver.so -b server.dll -g latest-gamedata.json
  sigscan-ts -b /path/to/binaries_dir -g latest-gamedata.json
`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  const options: {
    binaries: string[];
    pattern?: string;
    gamedata?: string;
    fast?: boolean;
    platform?: string;
    limit?: string;
    offset?: string;
  } = { binaries: [] };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "-h" || arg === "--help") {
      printHelp();
      process.exit(0);
    }
    if (arg === "-v" || arg === "--version") {
      console.log(`v${getPackageVersion()}`);
      process.exit(0);
    }

    if (arg === "--fast") {
      options.fast = true;
      continue;
    }

    if (arg === "-b" || arg === "--binary") {
      const val = args[++i];
      if (val) options.binaries.push(val);
    } else if (arg === "-p" || arg === "--pattern") {
      options.pattern = args[++i] || "";
    } else if (arg === "-g" || arg === "--gamedata") {
      options.gamedata = args[++i] || "";
    } else if (arg === "--platform") {
      options.platform = args[++i] || "";
    } else if (arg === "-l" || arg === "--limit") {
      options.limit = args[++i] || "";
    } else if (arg === "-o" || arg === "--offset") {
      options.offset = args[++i] || "";
    }
  }

  return options;
}

function parsePositiveInt(value: string | undefined, label: string, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || Number.isNaN(parsed) || parsed < 0) {
    console.error(`\x1b[31mError: Invalid ${label}: ${value}\x1b[0m`);
    process.exit(1);
  }
  return parsed;
}

function parsePlatform(value: string): "linux" | "windows" {
  const platform = value.toLowerCase();
  if (platform === "linux" || platform === "windows") {
    return platform;
  }
  console.error(`\x1b[31mError: Invalid --platform value: ${value}. Use "linux" or "windows".\x1b[0m`);
  process.exit(1);
}

function main() {
  const options = parseArgs();

  if (options.binaries.length === 0) {
    console.error("\x1b[31mError: Missing required option --binary <file>.\x1b[0m");
    printHelp();
    process.exit(1);
  }

  for (const bin of options.binaries) {
    if (!existsSync(bin)) {
      console.error(`\x1b[31mError: Binary file/directory not found: ${bin}\x1b[0m`);
      process.exit(1);
    }
  }

  if (!options.pattern && !options.gamedata) {
    console.error("\x1b[31mError: Must specify either --pattern <sig> or --gamedata <file>.\x1b[0m");
    printHelp();
    process.exit(1);
  }

  if (options.pattern) {
    for (const bin of options.binaries) {
      const isDirectory = statSync(bin).isDirectory();
      if (isDirectory) {
        console.error(`\x1b[31mError: --binary must be a file when scanning patterns: ${bin}\x1b[0m`);
        process.exit(1);
      }

      console.log(`Loading binary: ${bin}...`);
      const start = performance.now();
      let buffer: Buffer;
      try {
        buffer = readFileSync(bin);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`\x1b[31mError reading file: ${msg}\x1b[0m`);
        process.exit(1);
      }
      console.log(`Loaded binary (${(buffer.length / 1024 / 1024).toFixed(2)} MB) in ${(performance.now() - start).toFixed(2)}ms`);
      const scanner = new PatternScanner(buffer);
      const limit = parsePositiveInt(options.limit, "--limit", 0);
      const startOffset = parsePositiveInt(options.offset, "--offset", 0);

      console.log(`Scanning [${bin}] for pattern: "${options.pattern}"${options.fast ? " [fast]" : ""}...`);
      const scanStart = performance.now();
      const result = scanner.scan(options.pattern, options.fast ? { limit, startOffset, fast: true } : { limit, startOffset });
      const duration = performance.now() - scanStart;

      console.log(`Scan completed in ${duration.toFixed(2)}ms`);
      if (result.found) {
        const matchesLabel = options.fast && result.offsets.length >= 2 ? "2+" : String(result.offsets.length);
        console.log(`\n\x1b[32mFOUND ${matchesLabel} MATCHES in [${bin}]:\x1b[0m`);
        result.offsets.forEach((offset, idx) => {
          console.log(`  Match #${idx + 1}: Offset \x1b[36m0x${offset.toString(16)}\x1b[0m (${offset})`);
        });
        console.log(`Reliable (unique): ${result.reliable ? "\x1b[32mYes\x1b[0m" : "\x1b[33mNo (multiple/none)\x1b[0m"}`);
      } else {
        console.log(`\n\x1b[31mPATTERN NOT FOUND in [${bin}]\x1b[0m`);
      }
    }
  }

  // Mode 3: Gamedata Batch-Verify
  if (options.gamedata) {
    console.log(`Loading gamedata: ${options.gamedata}...`);
    interface GamedataEntry {
      signatures?: {
        library: string;
        windows?: string;
        linux?: string;
      };
      offsets?: Record<string, number>;
      lib?: string;
      windows?: string | number;
      linux?: string | number;
    }
    let gamedata: Record<string, GamedataEntry>;
    try {
      gamedata = JSON.parse(readFileSync(options.gamedata, "utf8")) as Record<string, GamedataEntry>;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`\x1b[31mError reading gamedata JSON: ${msg}\x1b[0m`);
      process.exit(1);
    }

    // Determine platforms to verify
    const platforms: ("linux" | "windows")[] = [];
    if (options.platform) {
      platforms.push(parsePlatform(options.platform));
    } else {
      // Auto-detect based on provided binaries
      for (const bin of options.binaries) {
        const isDir = statSync(bin).isDirectory();
        if (isDir) {
          if (existsSync(join(bin, "server.dll"))) {
            platforms.push("windows");
          }
          if (existsSync(join(bin, "libserver.so"))) {
            platforms.push("linux");
          }
        } else {
          if (bin.toLowerCase().endsWith(".dll")) {
            platforms.push("windows");
          } else if (bin.toLowerCase().endsWith(".so")) {
            platforms.push("linux");
          }
        }
      }
      // Deduplicate
      if (platforms.length === 0) {
        platforms.push("linux"); // fallback default
      }
    }

    const uniquePlatforms = Array.from(new Set(platforms));
    const loadedBinaries = new Map<string, PatternScanner>();

    let passedTotal = 0;
    let warningsTotal = 0;
    let failedTotal = 0;
    let skippedTotal = 0;

    const entries = Object.entries(gamedata);
    console.log(`Verifying signatures for platforms: \x1b[35m${uniquePlatforms.join(", ")}\x1b[0m`);
    console.log(`Found ${entries.length} entries. Starting scan...\n`);

    for (const [name, entry] of entries) {
      const results: Record<string, { status: "OK" | "WARN" | "FAIL" | "SKIP" | "ERR"; detail: string }> = {};

      for (const platform of uniquePlatforms) {
        // 1. Resolve library name and signature pattern
        let library = "server";
        let sigPattern: string | null = null;
        let hasOffset = false;

        if (entry.signatures && typeof entry.signatures === "object") {
          library = entry.signatures.library || "server";
          sigPattern = entry.signatures[platform] || null;
          hasOffset = entry.offsets?.[platform] !== undefined;
        } else if (entry.lib || (entry.windows && entry.linux)) {
          library = entry.lib || "server";
          const val = entry[platform];
          if (typeof val === "string") {
            sigPattern = val;
          } else if (typeof val === "number") {
            hasOffset = true;
          }
        } else {
          const val = entry[platform];
          if (typeof val === "string") {
            sigPattern = val;
          } else if (typeof val === "number") {
            hasOffset = true;
          }
        }

        // If no signature pattern was found, skip it
        if (!sigPattern) {
          if (hasOffset) {
            results[platform] = { status: "SKIP", detail: "OFFSET ONLY" };
          } else {
            results[platform] = { status: "SKIP", detail: "NO SIG" };
          }
          continue;
        }

        // 2. Resolve target binary file path
        const targetFileName = platform === "windows" ? `${library.toLowerCase()}.dll` : `lib${library.toLowerCase()}.so`;
        let binaryFilePath: string | null = null;

        // Try to match from provided binaries
        for (const bin of options.binaries) {
          const isDir = statSync(bin).isDirectory();
          if (isDir) {
            const fullPath = join(bin, targetFileName);
            if (existsSync(fullPath)) {
              binaryFilePath = fullPath;
              break;
            }
          } else {
            if (bin.toLowerCase().endsWith(targetFileName.toLowerCase())) {
              binaryFilePath = bin;
              break;
            }
            const parentPath = join(dirname(bin), targetFileName);
            if (existsSync(parentPath)) {
              binaryFilePath = parentPath;
              break;
            }
          }
        }

        // Fallback: If not resolved, check if any of the provided files matches this platform
        if (!binaryFilePath) {
          for (const bin of options.binaries) {
            if (!statSync(bin).isDirectory()) {
              const isBinLinux = bin.toLowerCase().endsWith(".so") || !bin.toLowerCase().endsWith(".dll");
              const binPlatform = isBinLinux ? "linux" : "windows";
              if (binPlatform === platform) {
                binaryFilePath = bin;
                break;
              }
            }
          }
        }

        if (!binaryFilePath || !existsSync(binaryFilePath)) {
          results[platform] = { status: "ERR", detail: "FILE NOT FOUND" };
          continue;
        }

        // 3. Load/Get the PatternScanner for this library on-demand
        let currentAnalyzer = loadedBinaries.get(binaryFilePath);
        if (!currentAnalyzer) {
          try {
            const fileBuf = readFileSync(binaryFilePath);
            currentAnalyzer = new PatternScanner(fileBuf);
            loadedBinaries.set(binaryFilePath, currentAnalyzer);
          } catch (err) {
            results[platform] = { status: "ERR", detail: "LOAD FAILED" };
            continue;
          }
        }

        // 4. Scan
        try {
          const result = currentAnalyzer.scan(sigPattern);
          if (result.found) {
            if (result.reliable) {
              const offsetHex = `0x${result.offsets[0]!.toString(16).toUpperCase()}`;
              results[platform] = { status: "OK", detail: offsetHex };
            } else {
              results[platform] = { status: "WARN", detail: `MULTIPLE (${result.offsets.length})` };
            }
          } else {
            results[platform] = { status: "FAIL", detail: "NOT FOUND" };
          }
        } catch (err) {
          results[platform] = { status: "ERR", detail: "SCAN ERROR" };
        }
      }

      // Determine overall status based on priority: FAIL > ERR > WARN > OK > SKIP
      let overallStatus: "OK" | "WARN" | "FAIL" | "SKIP" | "ERR" = "SKIP";
      const statusPriority: ("SKIP" | "OK" | "WARN" | "ERR" | "FAIL")[] = ["SKIP", "OK", "WARN", "ERR", "FAIL"];

      for (const platform of uniquePlatforms) {
        const platRes = results[platform];
        if (platRes) {
          const currentIdx = statusPriority.indexOf(overallStatus);
          const newIdx = statusPriority.indexOf(platRes.status);
          if (newIdx > currentIdx) {
            overallStatus = platRes.status;
          }
        }
      }

      // Increment overall stats counter
      if (overallStatus === "FAIL" || overallStatus === "ERR") {
        failedTotal++;
      } else if (overallStatus === "WARN") {
        warningsTotal++;
      } else if (overallStatus === "OK") {
        passedTotal++;
      } else {
        skippedTotal++;
      }

      // Format line prefix
      let statusLabel = "";
      if (overallStatus === "FAIL" || overallStatus === "ERR") {
        statusLabel = "\x1b[31m[ FAIL ]\x1b[0m";
      } else if (overallStatus === "WARN") {
        statusLabel = "\x1b[33m[ WARN ]\x1b[0m";
      } else if (overallStatus === "OK") {
        statusLabel = "\x1b[32m[  OK  ]\x1b[0m";
      } else {
        statusLabel = "\x1b[90m[ SKIP ]\x1b[0m";
      }

      // Build platform status strings
      const platStrings = uniquePlatforms.map((platform) => {
        const platRes = results[platform];
        const label = platform === "linux" ? "Linux" : "Windows";
        if (!platRes) {
          return `${label}: \x1b[90mNO SIG\x1b[0m`;
        }

        let detailStr = platRes.detail;
        if (platRes.status === "OK") {
          detailStr = `\x1b[36m${platRes.detail}\x1b[0m`;
        } else if (platRes.status === "FAIL" || platRes.status === "ERR") {
          detailStr = `\x1b[31m${platRes.detail}\x1b[0m`;
        } else if (platRes.status === "WARN") {
          detailStr = `\x1b[33m${platRes.detail}\x1b[0m`;
        } else {
          detailStr = `\x1b[90m${platRes.detail}\x1b[0m`;
        }
        return `${label}: ${detailStr}`;
      });

      // Get library name for display (defaults to "server" if not defined)
      let displayLib = "server";
      if (entry.signatures && typeof entry.signatures === "object") {
        displayLib = entry.signatures.library || "server";
      } else if (entry.lib) {
        displayLib = entry.lib;
      }

      console.log(`${statusLabel} \x1b[1m${name}\x1b[0m \x1b[90m(${displayLib})\x1b[0m | ${platStrings.join(" | ")}`);
    }

    console.log(`\n\x1b[1m=== Scan Summary ===\x1b[0m`);
    console.log(`Total entries:     ${entries.length}`);
    console.log(`\x1b[32mUnique matches:    ${passedTotal}\x1b[0m`);
    console.log(`\x1b[33mMultiple matches:  ${warningsTotal}\x1b[0m`);
    console.log(`\x1b[31mFailed/Broken:     ${failedTotal}\x1b[0m`);
    console.log(`\x1b[90mSkipped/No Sig:    ${skippedTotal}\x1b[0m`);

    if (failedTotal > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  }
}

main();

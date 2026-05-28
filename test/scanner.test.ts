import { describe, expect, it, beforeAll, afterAll } from "bun:test";
import { parsePattern, PatternScanner, scan } from "../src/index.js";

describe("Pattern Parser", () => {
  it("should parse standard IDA patterns with spaces", () => {
    const pattern = "48 8B C4 ? 53 ?? 90";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should parse x64dbg dot patterns", () => {
    const pattern = "48.8B.C4.?.53.??.90";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should parse backslash-x escaped patterns", () => {
    const pattern = "\\x48 \\x8B \\xC4 ? \\x53 ?? \\x90";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should parse raw unspaced hex strings", () => {
    const pattern = "488bc4??53??90";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should parse C-style arrays with commas, brackets, and 0x prefixes", () => {
    const pattern = "{ 0x48, 0x8B, 0xC4, ??, 0x53, ?, 0x90 }";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should parse patterns with 0x prefixes and spaces", () => {
    const pattern = "0x48 0x8b 0xc4 ?? 0x53 ?? 0x90";
    const parsed = parsePattern(pattern);
    expect(parsed).toEqual([0x48, 0x8b, 0xc4, null, 0x53, null, 0x90]);
  });

  it("should throw error on invalid hex tokens", () => {
    expect(() => parsePattern("48 8B ZZ")).toThrow();
  });
});

describe("Pattern Scanner", () => {
  // Test buffer: 0x00 to 0x19
  const buffer = Buffer.from([0x00, 0x11, 0x22, 0x33, 0x48, 0x8b, 0xc4, 0x55, 0x53, 0x66, 0x90, 0x99, 0x00, 0x11, 0x22, 0x33, 0x48, 0x8b, 0xc4, 0xaa, 0x53, 0xbb, 0x90, 0xaa]);

  it("should scan patterns without wildcards (native fast-path)", () => {
    const pattern = "48 8b c4";
    const scanner = new PatternScanner(buffer);
    const offsets = scanner.findPattern(pattern);
    expect(offsets).toEqual([4, 16]);
  });

  it("should scan patterns with wildcards in the middle (prefix optimization path)", () => {
    const pattern = "48 8b c4 ? 53";
    const scanner = new PatternScanner(buffer);
    const result = scanner.scan(pattern);

    expect(result.found).toBe(true);
    expect(result.offsets).toEqual([4, 16]);
    expect(result.reliable).toBe(false); // two matches found
  });

  it("should keep reliable false when limit hides duplicate matches", () => {
    const pattern = "48 8b c4";
    const result = scan(buffer, pattern, { limit: 1 });

    expect(result.found).toBe(true);
    expect(result.offsets).toEqual([4]);
    expect(result.reliable).toBe(false);
  });

  it("should stop after the second match in fast mode", () => {
    const pattern = "48 8b c4";
    const scanner = new PatternScanner(buffer);
    const result = scanner.scan(pattern, { fast: true });

    expect(result.found).toBe(true);
    expect(result.offsets).toEqual([4, 16]);
    expect(result.reliable).toBe(false);
  });

  it("should scan patterns with wildcards at the beginning (linear fallback path)", () => {
    const pattern = "? 8b c4 55";
    const result = scan(buffer, pattern);

    expect(result.found).toBe(true);
    expect(result.offsets).toEqual([4]);
    expect(result.reliable).toBe(true); // exactly 1 match
  });

  it("should respect limit option", () => {
    const pattern = "48 8b c4";
    const result = scan(buffer, pattern, { limit: 1 });
    expect(result.offsets).toEqual([4]);
  });

  it("should respect startOffset option", () => {
    const pattern = "48 8b c4";
    const result = scan(buffer, pattern, { startOffset: 5 });
    expect(result.offsets).toEqual([16]);
  });

  it("should return empty array if pattern not found", () => {
    const pattern = "FF FF FF FF";
    const result = scan(buffer, pattern);
    expect(result.found).toBe(false);
    expect(result.offsets).toEqual([]);
    expect(result.reliable).toBe(false);
  });

  it("should handle pattern larger than data", () => {
    const pattern = "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA";
    const result = scan(buffer, pattern);
    expect(result.found).toBe(false);
    expect(result.offsets).toEqual([]);
  });
});
describe("CLI Tools", () => {
  const { execSync } = require("child_process");
  const { writeFileSync, unlinkSync } = require("fs");

  const binaryPath = "./test_cli_dummy.bin";
  const gamedataPath = "./test_cli_gamedata.json";

  beforeAll(() => {
    const dummyBytes = Buffer.concat([
      Buffer.from([0x55, 0x48, 0x89, 0xe5]),
      Buffer.from([0x48, 0x8d, 0x3d]),
      Buffer.from([0x00, 0x00, 0x00, 0x00]),
      Buffer.from("hello\0", "utf8")
    ]);
    writeFileSync(binaryPath, dummyBytes);

    const gamedata = {
      TestFunc: {
        signatures: {
          linux: "55 48 89 E5",
          windows: "48 8D 3D"
        }
      },
      NoSigFunc: {
        offsets: {
          linux: 12
        }
      }
    };
    writeFileSync(gamedataPath, JSON.stringify(gamedata));
  });

  afterAll(() => {
    try {
      unlinkSync(binaryPath);
    } catch {}
    try {
      unlinkSync(gamedataPath);
    } catch {}
  });

  it("should output help menu when run without arguments", () => {
    try {
      execSync("bun run src/cli.ts");
      expect(false).toBe(true);
    } catch (err: any) {
      expect(err.status).toBe(1);
      expect(err.stderr.toString()).toContain("Error: Missing required option");
    }
  });

  it("should reject invalid platform values", () => {
    try {
      execSync(`bun run src/cli.ts -b ${binaryPath} -g ${gamedataPath} --platform invalid`);
      expect(false).toBe(true);
    } catch (err: any) {
      expect(err.status).toBe(1);
      expect(err.stderr.toString()).toContain('Error: Invalid --platform value: invalid. Use "linux" or "windows".');
    }
  });

  it("should successfully find pattern via CLI", () => {
    const output = execSync(`bun run src/cli.ts -b ${binaryPath} -p "55 48 89 E5"`).toString();
    expect(output).toContain("FOUND 1 MATCHES");
    expect(output).toContain("0x0");
  });

  it("should verify gamedata batch-scan via CLI", () => {
    const output = execSync(`bun run src/cli.ts -b ${binaryPath} -g ${gamedataPath} --platform linux`).toString();
    expect(output).toContain("Unique matches:    1");
    expect(output).toContain("Failed/Broken:     0");
    expect(output).toContain("TestFunc");
    expect(output).toContain("OK");
  });
});

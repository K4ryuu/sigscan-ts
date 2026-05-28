import { describe, expect, it, beforeAll, afterAll } from "bun:test";
import { parsePattern, PatternScanner, BinaryAnalyzer, scan } from "../src/index.js";

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
  const buffer = Buffer.from([
    0x00, 0x11, 0x22, 0x33, 0x48, 0x8b, 0xc4, 0x55, 0x53, 0x66, 0x90, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x48, 0x8b, 0xc4, 0xaa, 0x53, 0xbb, 0x90, 0xaa
  ]);

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

describe("Advanced String Scanner Features", () => {
  // Construct a mock x64 binary buffer:
  // - Function prologue starts at offset 0: 55 48 89 e5
  // - LEA RDI, [RIP + displacement] starts at offset 4: 48 8d 3d [09 00 00 00]
  //   Instruction size is 7. Displacement starts at offset 7.
  //   Next instruction starts at 4 + 7 = 11.
  //   String target is at offset 20. (11 + 9 = 20).
  // - String "test\0" starts at offset 20.
  const mockBinary = Buffer.concat([
    Buffer.from([0x55, 0x48, 0x89, 0xe5]), // 0-3: prologue
    Buffer.from([0x48, 0x8d, 0x3d]),       // 4-6: LEA opcode
    Buffer.from([0x09, 0x00, 0x00, 0x00]), // 7-10: displacement (9)
    Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]), // 11-19: padding NOPs
    Buffer.from("test\0", "utf8")          // 20-24: "test\0" string
  ]);

  it("should find the offset of a string literal", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    const offset = scanner.findString("test");
    expect(offset).toBe(20);
  });

  it("should dump printable strings in the binary", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    const strings = scanner.dumpStrings({ minLength: 4 });
    expect(strings).toContainEqual({ offset: 20, text: "test" });
  });

  it("should trace RIP-relative string references", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    const refs = scanner.findStringReferences(20);
    
    expect(refs.length).toBe(1);
    expect(refs[0]?.instructionOffset).toBe(4);
    expect(refs[0]?.displacementOffset).toBe(7);
  });

  it("should scan backwards to find function prologue start", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    const funcStart = scanner.findFunctionStart(4);
    expect(funcStart).toBe(0);
  });

  it("should automatically generate signature for function referencing a string", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    const result = scanner.generateSignatureFromString("test", 11);
    
    expect(result).not.toBeNull();
    expect(result?.offset).toBe(0);
    // The signature should wildcard the 4-byte displacement at offset 7 to 10
    expect(result?.signature).toBe("55 48 89 E5 48 8D 3D ?? ?? ?? ??");
  });

  it("should handle generateSignatureFromString edge cases (null results)", () => {
    const scanner = new BinaryAnalyzer(mockBinary);
    
    // Case 1: String does not exist in binary
    expect(scanner.generateSignatureFromString("nonexistent")).toBeNull();

    // Case 2: String exists but is not referenced in code
    const noRefBinary = Buffer.concat([
      Buffer.from([0x55, 0x48, 0x89, 0xe5]),
      Buffer.from("dummy\0", "utf8")
    ]);
    const noRefScanner = new BinaryAnalyzer(noRefBinary);
    expect(noRefScanner.generateSignatureFromString("dummy")).toBeNull();

    // Case 3: String is referenced but no prologue is found
    const noPrologueBinary = Buffer.concat([
      Buffer.from([0x90, 0x90, 0x90, 0x90]), // NOP padding only, no prologue
      Buffer.from([0x48, 0x8d, 0x3d]),       // LEA instruction
      Buffer.from([0x05, 0x00, 0x00, 0x00]), // displacement
      Buffer.from("noprologue\0", "utf8")   // target string
    ]);
    const noPrologueScanner = new BinaryAnalyzer(noPrologueBinary);
    expect(noPrologueScanner.generateSignatureFromString("noprologue")).toBeNull();
  });

  it("should scan backwards to find GCC imm32 function prologue", () => {
    const imm32Binary = Buffer.concat([
      Buffer.from([0x55, 0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00]), // 0-7: GCC imm32 prologue (push rbp; sub rsp, 4096)
      Buffer.from([0x48, 0x8d, 0x3d]),                              // 8-10: LEA instruction
      Buffer.from([0x00, 0x00, 0x00, 0x00]),                        // 11-14: displacement (0)
      Buffer.from("imm32\0", "utf8")                                // 15-21: string
    ]);
    const scanner = new BinaryAnalyzer(imm32Binary);
    const funcStart = scanner.findFunctionStart(8);
    expect(funcStart).toBe(0);
    
    const sig = scanner.generateSignatureFromString("imm32", 15);
    expect(sig?.offset).toBe(0);
    // Verified displacement wildcard mapping
    expect(sig?.signature).toBe("55 48 81 EC 00 10 00 00 48 8D 3D ?? ?? ?? ??");
  });

  it("should throw error if isBuffer is false for string scanning", () => {
    const mockArray = new Uint8Array([0]);
    const scanner = new BinaryAnalyzer(mockArray);
    
    // Force isBuffer to be false to simulate browser/non-Node environment
    Object.defineProperty(scanner, "isBuffer", { value: false });

    expect(() => scanner.findString("test")).toThrow();
    expect(() => scanner.dumpStrings()).toThrow();
    expect(() => scanner.findStringReferences(0)).toThrow();
    expect(() => scanner.findFunctionStart(0)).toThrow();
  });

  it("should dump string at the very end of the buffer", () => {
    const endBinary = Buffer.from("nopad_hello", "utf8"); // 11 bytes, no null terminator
    const scanner = new BinaryAnalyzer(endBinary);
    const strings = scanner.dumpStrings({ minLength: 4 });
    expect(strings).toEqual([{ offset: 0, text: "nopad_hello" }]);
  });

  it("should scan backwards to find MSVC function prologues", () => {
    // MSVC push rbx (40 53)
    const msvcPushRbxBinary = Buffer.from([0x40, 0x53, 0x90, 0x90, 0x90]);
    const scanner1 = new BinaryAnalyzer(msvcPushRbxBinary);
    expect(scanner1.findFunctionStart(4)).toBe(0);

    // MSVC sub rsp, imm (48 83 EC)
    const msvcSubRspBinary = Buffer.from([0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90]);
    const scanner2 = new BinaryAnalyzer(msvcSubRspBinary);
    expect(scanner2.findFunctionStart(5)).toBe(0);
  });

  it("should validate constructor and method inputs", () => {
    // Constructor input validation
    expect(() => new PatternScanner(null as any)).toThrow();
    expect(() => new PatternScanner(123 as any)).toThrow();
    expect(() => new PatternScanner("string" as any)).toThrow();

    // parsePattern validation
    expect(() => parsePattern(null as any)).toThrow("parsePattern: pattern argument must be a string");
    expect(() => parsePattern(123 as any)).toThrow("parsePattern: pattern argument must be a string");

    // findPattern validation
    const scanner = new PatternScanner(Buffer.from([0x00]));
    expect(() => scanner.findPattern(null as any)).toThrow("PatternScanner: pattern argument must be a string or PatternByte array");
    expect(() => scanner.findPattern(123 as any)).toThrow("PatternScanner: pattern argument must be a string or PatternByte array");
  });

  describe("CLI Tools", () => {
    const { execSync } = require("child_process");
    const { writeFileSync, unlinkSync } = require("fs");
    
    const binaryPath = "./test_cli_dummy.bin";
    const gamedataPath = "./test_cli_gamedata.json";

    beforeAll(() => {
      // Write dummy binary: contains a pattern "55 48 89 E5" and a string reference
      const dummyBytes = Buffer.concat([
        Buffer.from([0x55, 0x48, 0x89, 0xE5]), // prologue
        Buffer.from([0x48, 0x8D, 0x3D]),       // LEA
        Buffer.from([0x00, 0x00, 0x00, 0x00]), // displacement (0) targeting offset 11 (7 + 4 + 0 = 11)
        Buffer.from("hello\0", "utf8")        // string at 11
      ]);
      writeFileSync(binaryPath, dummyBytes);

      // Write dummy gamedata
      const gamedata = {
        "TestFunc": {
          "signatures": {
            "linux": "55 48 89 E5",
            "windows": "48 8D 3D"
          }
        },
        "NoSigFunc": {
          "offsets": {
            "linux": 12
          }
        }
      };
      writeFileSync(gamedataPath, JSON.stringify(gamedata));
    });

    afterAll(() => {
      try { unlinkSync(binaryPath); } catch {}
      try { unlinkSync(gamedataPath); } catch {}
    });

    it("should output help menu when run without arguments", () => {
      try {
        execSync("bun run src/cli.ts");
        expect(false).toBe(true); // Should not reach here
      } catch (err: any) {
        expect(err.status).toBe(1);
        expect(err.stderr.toString()).toContain("Error: Missing required option");
      }
    });

    it("should successfully find pattern via CLI", () => {
      const output = execSync(`bun run src/cli.ts -b ${binaryPath} -p "55 48 89 E5"`).toString();
      expect(output).toContain("FOUND 1 MATCHES");
      expect(output).toContain("0x0");
    });

    it("should generate signature from string via CLI", () => {
      const output = execSync(`bun run src/cli.ts -b ${binaryPath} -s "hello"`).toString();
      expect(output).toContain("SUCCESSFULLY GENERATED SIGNATURE");
      expect(output).toContain("55 48 89 E5 48 8D 3D ?? ?? ?? ??");
    });

    it("should verify gamedata batch-scan via CLI", () => {
      const output = execSync(`bun run src/cli.ts -b ${binaryPath} -g ${gamedataPath} --platform linux`).toString();
      expect(output).toContain("Unique matches:    1");
      expect(output).toContain("Failed/Broken:     0");
      expect(output).toContain("TestFunc");
      expect(output).toContain("OK");
    });
  });
});

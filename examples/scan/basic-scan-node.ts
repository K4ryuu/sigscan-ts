import { readFileSync, unlinkSync, writeFileSync } from "fs";
import { PatternScanner, scan } from "../../src/index.js";

const tempPath = "./dummy_app.bin";
writeFileSync(tempPath, Buffer.from([0x90, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3]));

try {
  const buf = readFileSync(tempPath);
  const scanner = new PatternScanner(buf);

  // IDA Pro style
  console.log(
    "IDA:",
    scanner.findPattern("55 48 89 E5 ?? ?? EC").map((o) => `0x${o.toString(16)}`)
  );

  // x64dbg dot-separated
  console.log(
    "x64dbg:",
    scanner.findPattern("55.48.89.E5.??.??.EC").map((o) => `0x${o.toString(16)}`)
  );

  // C-style array
  console.log(
    "C-array:",
    scanner.findPattern("{ 0x55, 0x48, 0x89, 0xE5, ??, ??, 0xEC }").map((o) => `0x${o.toString(16)}`)
  );

  // one-off helper
  console.log("scan():", scan(buf, "B8 01 00 00 00"));
} finally {
  unlinkSync(tempPath);
}

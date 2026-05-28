import { readFileSync, writeFileSync, unlinkSync } from "fs";
import { PatternScanner, scan } from "../../src/index.js";

// --- Node.js Optimal Pattern Scanning ---
// In Node.js, readFileSync returns a Buffer. 
// sigscan-ts is highly optimized for Buffers, executing search loops in native C++ via indexOf.
function runDemo() {
  // 1. Create a dummy binary file for demonstration
  const tempFilePath = "./dummy_app.bin";
  const dummyBytes = Buffer.from([
    0x90, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, // Prologue & Stack alloc
    0xB8, 0x01, 0x00, 0x00, 0x00,                               // mov eax, 1
    0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3,                         // Epilogue & ret
  ]);
  writeFileSync(tempFilePath, dummyBytes);

  try {
    // 2. Read the file (readFileSync returns a Node Buffer, which is the most optimal format)
    console.log(`Reading binary: ${tempFilePath}...`);
    const fileBuffer = readFileSync(tempFilePath);

    // 3. Instantiate the scanner
    const scanner = new PatternScanner(fileBuffer);

    // --- Search using different pattern formats ---
    
    // IDA Pro style:
    const idaOffset = scanner.findPattern("55 48 89 E5 ?? ?? EC");
    console.log("IDA Pro match offset:", idaOffset.map(o => `0x${o.toString(16)}`)); // [0x2]

    // x64dbg style:
    const x64Offset = scanner.findPattern("55.48.89.E5.??.??.EC");
    console.log("x64dbg match offset:", x64Offset.map(o => `0x${o.toString(16)}`)); // [0x2]

    // C-Style Array format:
    const cArrayOffset = scanner.findPattern("{ 0x55, 0x48, 0x89, 0xE5, ??, ??, 0xEC }");
    console.log("C-style array match offset:", cArrayOffset.map(o => `0x${o.toString(16)}`)); // [0x2]

    // 4. One-off quick scan helper
    const result = scan(fileBuffer, "B8 01 00 00 00");
    console.log("\nOne-off scan result:", result);
    // { found: true, offsets: [ 10 ], reliable: true }

  } finally {
    // Cleanup the dummy file
    unlinkSync(tempFilePath);
  }
}

runDemo();

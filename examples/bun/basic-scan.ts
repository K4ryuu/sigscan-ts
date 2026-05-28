import { PatternScanner, scan } from "../../src/index.js";

// --- Bun Native Pattern Scanning ---
// Bun uses 'Bun.file' for fast asynchronous file I/O.
// sigscan-ts works out of the box with Bun's ArrayBuffers and Uint8Arrays.
// Because Bun natively supports the global Buffer class, sigscan-ts automatically
// wraps Uint8Arrays into Buffers internally to achieve maximum native performance!
async function runDemo() {
  const tempFilePath = "./dummy_app_bun.bin";
  
  // 1. Create a dummy binary file using Bun's fast writer
  const dummyBytes = new Uint8Array([
    0x90, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, // Prologue & Stack alloc
    0xB8, 0x01, 0x00, 0x00, 0x00,                               // mov eax, 1
    0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3,                         // Epilogue & ret
  ]);
  await Bun.write(tempFilePath, dummyBytes);

  try {
    // 2. Read the file into an ArrayBuffer using Bun.file
    console.log(`Reading binary via Bun.file: ${tempFilePath}...`);
    const file = Bun.file(tempFilePath);
    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);

    // 3. Scan the binary data
    const scanner = new PatternScanner(data);

    // IDA Pro style signature:
    const idaOffset = scanner.findPattern("55 48 89 E5 ?? ?? EC");
    console.log("IDA Pro match offset:", idaOffset.map(o => `0x${o.toString(16)}`)); // [0x2]

    // One-off scan using the simple helper function:
    const result = scan(data, "B8 01 ?? ?? 00");
    console.log("\nOne-off scan result:", result);
    // { found: true, offsets: [ 10 ], reliable: true }

  } finally {
    // Cleanup using standard file API
    const { unlinkSync } = await import("fs");
    unlinkSync(tempFilePath);
  }
}

runDemo();

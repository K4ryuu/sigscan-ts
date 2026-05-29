import { PatternScanner, scan } from "../../src/index.js";

const dummyBytes = new Uint8Array([0x90, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3]);

const tempPath = "./dummy_app_bun.bin";
await Bun.write(tempPath, dummyBytes);

try {
  const data = new Uint8Array(await Bun.file(tempPath).arrayBuffer());
  const scanner = new PatternScanner(data);

  // IDA Pro style
  console.log(
    "IDA:",
    scanner.findPattern("55 48 89 E5 ?? ?? EC").map((o) => `0x${o.toString(16)}`)
  );

  // one-off helper
  console.log("scan():", scan(data, "B8 01 ?? ?? 00"));
} finally {
  const { unlinkSync } = await import("fs");
  unlinkSync(tempPath);
}

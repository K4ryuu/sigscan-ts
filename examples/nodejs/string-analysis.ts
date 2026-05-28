import { BinaryAnalyzer } from "../../src/index.js";

// --- Node.js Advanced String Reference & Signature Analysis ---
// Demonstrates how to locate strings, find where code references them, 
// and generate relocatable function signatures automatically.
function runDemo() {
  console.log("Constructing mock x64 binary in memory...");
  
  // Construct a mock binary structure:
  // - Function prologue starts at offset 0: 55 48 89 E5 (push rbp; mov rbp, rsp)
  // - LEA RDI, [RIP + displacement] starts at offset 4: 48 8D 3D [09 00 00 00]
  //   Instruction size is 7 bytes. Displacement starts at offset 7.
  //   Next instruction starts at 4 + 7 = 11.
  //   String target is at offset 20 (11 + 9 = 20).
  // - String "Hello_World\0" starts at offset 20.
  const mockBinary = Buffer.concat([
    Buffer.from([0x55, 0x48, 0x89, 0xE5]), // 0-3: function prologue
    Buffer.from([0x48, 0x8D, 0x3D]),       // 4-6: LEA instruction opcode
    Buffer.from([0x09, 0x00, 0x00, 0x00]), // 7-10: displacement value of 9
    Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]), // 11-19: NOP padding
    Buffer.from("Hello_World\0", "utf8")   // 20-31: Null-terminated string literal
  ]);

  const analyzer = new BinaryAnalyzer(mockBinary);

  // 1. Find string offset
  const strOffset = analyzer.findString("Hello_World");
  console.log(`1. String "Hello_World" found at offset: 0x${strOffset?.toString(16)} (index ${strOffset})`);

  // 2. Dump all strings (Unix strings equivalent)
  const dumped = analyzer.dumpStrings({ minLength: 5 });
  console.log("\n2. Dumped strings in binary:", dumped);

  // 3. Find code references to the string
  if (strOffset !== null) {
    const refs = analyzer.findStringReferences(strOffset);
    console.log("\n3. Found RIP-relative references to string:");
    refs.forEach((ref, idx) => {
      console.log(`   Reference #${idx + 1}: Instruction starts at 0x${ref.instructionOffset.toString(16)}, Displacement at 0x${ref.displacementOffset.toString(16)}`);
    });

    // 4. Auto-generate relocatable function signature
    console.log("\n4. Generating relocatable IDA signature based on string reference...");
    const sigResult = analyzer.generateSignatureFromString("Hello_World", 11);
    if (sigResult) {
      console.log(`   Containing function start: 0x${sigResult.offset.toString(16)}`);
      console.log(`   Generated IDA Pattern:     ${sigResult.signature}`);
      
      // Note: The displacement bytes [09 00 00 00] at offset 7 were automatically wild-carded
      // to "?? ?? ?? ??" to make the signature robust against binary rebuilds/patches!

      // 5. Verify the generated signature
      console.log("\n5. Verifying the generated signature by scanning it back...");
      const verify = analyzer.scan(sigResult.signature);
      console.log("   Verify matches:", verify.offsets);
      console.log("   Reliable (unique)?", verify.reliable);
    }
  }
}

runDemo();

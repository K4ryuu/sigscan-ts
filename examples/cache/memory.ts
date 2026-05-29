import { LRUPatternCache, PatternScanner } from "../../src/index.js";

const data = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3]);

// default: shared LRU(256) across all instances, zero config
const scanner = new PatternScanner(data);
console.log("default:", scanner.findPattern("55 48 89 E5"));

// custom size: bump it if you're scanning hundreds of unique patterns
const scanner2 = new PatternScanner(data, { cache: new LRUPatternCache(1024) });
console.log("custom size:", scanner2.findPattern("55 48 89 E5"));

// disable entirely when every pattern is one-shot
const scanner3 = new PatternScanner(data, { cache: false });
console.log("no cache:", scanner3.findPattern("55 48 89 E5"));

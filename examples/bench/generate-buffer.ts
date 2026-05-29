import { randomFillSync } from "crypto";

// Concrete bytes planted into the buffer at known offsets
export const SIGNATURE = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04]);

export function generateBuffer(size: number): { buffer: Buffer; offsets: number[] } {
  const buffer = Buffer.allocUnsafe(size);
  randomFillSync(buffer);

  // Plant the signature at 3 predictable positions so scanners always find something
  const offsets = [Math.floor(size * 0.1), Math.floor(size * 0.5), Math.floor(size * 0.9)];
  for (const offset of offsets) SIGNATURE.copy(buffer, offset);

  return { buffer, offsets };
}

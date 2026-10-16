import { describe, expect, test } from "bun:test";
import { buildFrame, buildFrameExtended, parseFrame } from "./frame";

function decodeHex(value: string): Uint8Array {
  return new Uint8Array(value.replace(/\s/g, "").match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)));
}

describe("SOYAL frame codecs", () => {
  test("round-trips the protocol short-frame vectors", () => {
    const vectors = [
      "7E 04 00 04 FB FF",
      "7E 04 00 05 FA FF",
      "7E 04 00 06 F9 FF",
      "7E 04 00 07 F8 FF",
      "7E 04 01 18 E6 FF",
      "7E 04 01 25 DB 01",
      "7E 04 01 37 C9 01",
      "7E 05 01 21 84 5B 01",
      "7E 0B 01 23 07 1B 0A 02 02 05 16 D8 47",
      "7E 0B 01 23 07 1B 0A 05 10 06 16 CE 4F",
      "7E 0D 01 18 20 2B 0B 08 04 00 01 12 00 F9 87",
    ];
    for (const vector of vectors) {
      const raw = decodeHex(vector);
      const frame = parseFrame(raw);
      expect(Array.from(buildFrame(frame.did, frame.command, frame.data))).toEqual(Array.from(raw));
    }
  });

  test("round-trips the extended frame and stores area in the length nibble", () => {
    const data = new Uint8Array([0x01, 0x02, 0xa0]);
    const built = buildFrameExtended(0x03, 0x01, 0x23, data);
    expect(Array.from(built)).toEqual(Array.from(decodeHex("FF 00 5A A5 30 07 01 23 01 02 A0 7E 45")));
    expect(parseFrame(built)).toEqual({ did: 1, command: 0x23, data });
  });

  test("accepts the maximum short payload and rejects oversized data", () => {
    const data = new Uint8Array(240);
    data.forEach((_value, index) => { data[index] = index; });
    const frame = buildFrame(1, 0x23, data);
    expect(frame[1]).toBe(244);
    expect(Array.from(parseFrame(frame).data)).toEqual(Array.from(data));
    expect(() => buildFrame(1, 0x23, new Uint8Array(241))).toThrow();
  });

  test("validates both checksums, declared lengths, and security-mode rejection", () => {
    const valid = decodeHex("7E 05 01 21 84 5B 01");
    const corruptedXor = valid.slice();
    corruptedXor[corruptedXor.length - 2] ^= 1;
    expect(() => parseFrame(corruptedXor)).toThrow("XOR");
    const corruptedSum = valid.slice();
    corruptedSum[corruptedSum.length - 1] ^= 1;
    expect(() => parseFrame(corruptedSum)).toThrow("SUM");
    expect(() => parseFrame(valid.slice(0, -1))).toThrow("length");
    const wrongLength = valid.slice();
    wrongLength[1] += 1;
    expect(() => parseFrame(wrongLength)).toThrow("length");
    expect(() => parseFrame(decodeHex("7F 04 00 04 FB FF"))).toThrow("security mode frames are not supported");
    expect(() => parseFrame(decodeHex("FF 00 55 AA 00 04 00 04 00 00"))).toThrow("security mode frames are not supported");
  });
});

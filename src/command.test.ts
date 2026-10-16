import { describe, expect, test } from "bun:test";
import { buildEraseUserRangeBody, buildEventLogQueueStatusBody, buildEventLogRecordBody, buildGetParameterBody, buildHostingPollBody, buildOldestEventLogBody, buildReadClockBody, buildReadUserAliasBody, buildReadUserBody, buildSetClockBody } from "./command";

describe("SOYAL command body builders", () => {
  test("builds every supported requested body", () => {
    expect(Array.from(buildReadUserBody(0x1234, 3))).toEqual([0x87, 0x12, 0x34, 3]);
    expect(Array.from(buildReadUserAliasBody(0x123456, 3))).toEqual([0x2e, 0x12, 0x34, 0x56, 3]);
    expect(Array.from(buildEraseUserRangeBody(0x0102, 0x010a))).toEqual([0x85, 1, 2, 1, 10]);
    expect(Array.from(buildOldestEventLogBody())).toEqual([0x25]);
    expect(Array.from(buildEventLogQueueStatusBody())).toEqual([0x25, 0xff, 0xff, 0xff]);
    expect(Array.from(buildEventLogRecordBody(0x123456))).toEqual([0x25, 0x12, 0x34, 0x56]);
    expect(Array.from(buildReadClockBody())).toEqual([0x24]);
    expect(Array.from(buildSetClockBody(new Date(2026, 7, 18, 13, 14, 15)))).toEqual([0x23, 15, 14, 13, 3, 18, 8, 26]);
    expect(Array.from(buildHostingPollBody())).toEqual([0x18]);
    expect(Array.from(buildGetParameterBody(0xfe))).toEqual([0x12, 0xfe]);
  });

  test("enforces protocol address, range, and index limits", () => {
    expect(() => buildReadUserBody(0, 0)).toThrow("count");
    expect(() => buildReadUserBody(16384, 1)).toThrow("16383");
    expect(() => buildEraseUserRangeBody(10, 9)).toThrow("end address");
    expect(() => buildEraseUserRangeBody(0, 999)).toThrow("fewer than 1000");
    expect(() => buildEraseUserRangeBody(0, 16384)).toThrow("16383");
    expect(() => buildEventLogRecordBody(0x1000000)).toThrow("24-bit");
    expect(() => buildEraseUserRangeBody(0, 998)).not.toThrow();
    expect(() => buildReadUserBody(0x3ff7, 9)).not.toThrow();
    expect(() => buildReadUserBody(0x3ff8, 9)).toThrow("16383");
    // Nine 24-byte records plus the source-node byte is 217 data bytes. Ten
    // would be 241, and the protocol document caps a standard frame at 240.
    expect(() => buildReadUserBody(0, 10)).toThrow("at most 240");
    expect(() => buildReadUserBody(0, 255)).toThrow("at most 240");
    expect(() => buildReadUserAliasBody(0x1000000, 1)).toThrow("three bytes");
    expect(() => buildReadUserAliasBody(0, 0)).toThrow("count");
  });

  test("uses protocol weekday and century boundaries", () => {
    expect(Array.from(buildSetClockBody(new Date(2000, 0, 2, 3, 4, 5)))).toEqual([0x23, 5, 4, 3, 1, 2, 1, 0]);
    expect(Array.from(buildSetClockBody(new Date(2099, 11, 31, 23, 59, 58)))).toEqual([0x23, 58, 59, 23, 5, 31, 12, 99]);
    expect(() => buildSetClockBody(new Date(1999, 0, 1))).toThrow("2000");
    expect(() => buildSetClockBody(new Date(2100, 0, 1))).toThrow("2099");
  });

  test("builds a Taipei wall-clock write from a UTC instant", () => {
    expect(Array.from(buildSetClockBody(new Date("2026-09-15T07:00:00.000Z"), "Asia/Taipei"))).toEqual([0x23, 0, 0, 15, 3, 15, 9, 26]);
  });
});

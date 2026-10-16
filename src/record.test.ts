import { describe, expect, test } from "bun:test";
import { AccessMode, buildGuestAccessMode, buildMode, buildReadGuestAccessBody, buildSetGuestAccessBody, decodeGuestAccessRecord, decodeUserAliases, decodeUserRecord24, hasDoorAccess, parseGuestAccessMode, parseMode, setDoorAccess, uidString, type GuestAccessRecord, type ModeFlags, type UserRecord } from "./record";
import { encodeUserRecord } from "./record";

describe("SOYAL record codecs", () => {
  test("round-trips the 26-byte user record through the 24-byte read shape", () => {
    const modeFlags: ModeFlags = { accessMode: AccessMode.CardAndPin, patrol: true, cardOmittedAfterFingerprint: true, fingerprintOmittedAfterCard: false, enableExpireCheck: true, guest: true, passwordChangeAllowed: true };
    const record: UserRecord = {
      userAddress: 0x1234,
      tagUid: new Uint8Array([0x80, 1, 2, 3, 4, 5, 6, 7]),
      pinCode: 0x91234567,
      mode: buildMode(modeFlags),
      zone: 0xa5,
      group1: 0x80,
      group2: 1,
      year: 26,
      month: 8,
      day: 18,
      level: 0xc3,
      option: 0x80,
      reserved: new Uint8Array([0xaa, 0xbb, 0xcc]),
    };
    const encoded = encodeUserRecord(record);
    expect(encoded.length).toBe(26);
    expect(Array.from(encoded.slice(0, 2))).toEqual([0x12, 0x34]);
    const decoded = decodeUserRecord24(encoded.slice(2));
    expect(decoded).toEqual({ ...record, userAddress: 0 });
  });

  test("decodes fixed-width Traditional Chinese aliases as Big5 and treats FF padding as empty", () => {
    const aliases = new Uint8Array(32).fill(0xff);
    aliases.set([0xa4, 0x40, 0xa4, 0x42, 0x20], 0);
    expect(decodeUserAliases(aliases)).toEqual(["一丁", ""]);
  });

  test("packs and unpacks the user mode flags", () => {
    const flags: ModeFlags = { accessMode: AccessMode.CardOrPin, patrol: true, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: true, enableExpireCheck: true, guest: false, passwordChangeAllowed: true };
    expect(parseMode(buildMode(flags))).toEqual(flags);
    expect(buildMode({ ...flags, guest: true }) & 0x02).toBe(0x02);
  });

  test("maps doors 1-8 to group2 and 9-16 to group1", () => {
    let record: UserRecord = { userAddress: 0, tagUid: new Uint8Array(8), pinCode: 0, mode: 0, zone: 0, group1: 0, group2: 0, year: 0, month: 0, day: 0, level: 0, option: 0, reserved: new Uint8Array(3) };
    record = setDoorAccess(record, 1, true);
    record = setDoorAccess(record, 16, true);
    expect(record.group1).toBe(0x80);
    expect(record.group2).toBe(0x01);
    expect(hasDoorAccess(record, 1)).toBe(true);
    expect(hasDoorAccess(record, 16)).toBe(true);
    record = setDoorAccess(record, 1, false);
    expect(hasDoorAccess(record, 1)).toBe(false);
    expect(() => setDoorAccess(record, 0, true)).toThrow();
    expect(() => hasDoorAccess(record, 17)).toThrow();
  });

  test("round-trips 8BH guest records and keeps begin/end positions distinct", () => {
    const record: GuestAccessRecord = {
      userAddress: 0x123456,
      tagUid: new Uint8Array([1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
      pinCode: 0x10203040,
      mode: buildGuestAccessMode({ accessMode: AccessMode.CardAndPin, patrol: false, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: false, enableExpireCheck: true, checkBeginAndEndTime: true, passwordChangeAllowed: false }),
      zone: 0x11,
      group1: 0xa5,
      group2: 0x5a,
      beginYear: 26,
      beginMonth: 8,
      beginDay: 19,
      beginHour: 7,
      beginMinute: 8,
      endYear: 27,
      endMonth: 9,
      endDay: 20,
      endHour: 17,
      endMinute: 18,
      lift: new Uint8Array([0x10, 0x20, 0x30, 0x40]),
    };
    const encoded = buildSetGuestAccessBody(record);
    expect(encoded.length).toBe(35);
    expect(Array.from(encoded.slice(21, 26))).toEqual([26, 8, 19, 7, 8]);
    expect(Array.from(encoded.slice(26, 31))).toEqual([27, 9, 20, 17, 18]);
    const readEcho = encoded.slice();
    readEcho[1] = 0x52;
    expect(decodeGuestAccessRecord(readEcho)).toEqual(record);
    expect(parseGuestAccessMode(0x06).checkBeginAndEndTime).toBe(true);
    expect(parseMode(0x06).guest).toBe(true);
  });

  test("decodes the controller's address-plus-record 8BH read shape", () => {
    const record = new Uint8Array(30);
    record[0] = 0;
    record[1] = 0;
    record[2] = 42;
    record[3] = 0x00;
    record[4] = 0x00;
    record[5] = 0x00;
    record[7] = 0x57;
    record[8] = 0xb2;
    record[9] = 0x35;
    record[15] = 0x80;
    record[18] = 0x01;
    const decoded = decodeGuestAccessRecord(record);
    expect(decoded.userAddress).toBe(42);
    expect(uidString(decoded.tagUid)).toBe("0000000057B23500");
    expect(decoded.group2).toBe(1);
  });

  test("validates guest address and reserved bits", () => {
    expect(Array.from(buildReadGuestAccessBody(0xffffff))).toEqual([0x8b, 0x52, 0xff, 0xff, 0xff]);
    expect(() => buildReadGuestAccessBody(0x1000000)).toThrow();
    expect(() => buildSetGuestAccessBody({ userAddress: 0x1000000, tagUid: new Uint8Array(8), pinCode: 0, mode: 0, zone: 0, group1: 0, group2: 0, beginYear: 0, beginMonth: 0, beginDay: 0, beginHour: 0, beginMinute: 0, endYear: 0, endMonth: 0, endDay: 0, endHour: 0, endMinute: 0, lift: new Uint8Array(4) })).toThrow();
    const base = { userAddress: 0, tagUid: new Uint8Array(8), pinCode: 0, group1: 0, group2: 0, beginYear: 0, beginMonth: 0, beginDay: 0, beginHour: 0, beginMinute: 0, endYear: 0, endMonth: 0, endDay: 0, endHour: 0, endMinute: 0, lift: new Uint8Array(4) };
    expect(() => buildSetGuestAccessBody({ ...base, mode: 1, zone: 0 })).toThrow("Mode bit 0");
    expect(() => buildSetGuestAccessBody({ ...base, mode: 0, zone: 0x40 })).toThrow("Zone reserved");
  });

  test("treats an erased all-FF slot as holding no card", () => {
    expect(uidString(new Uint8Array(8).fill(0xff))).toBeUndefined();
    expect(uidString(new Uint8Array(8))).toBeUndefined();
    expect(uidString(new Uint8Array([0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd]))).toBe("00000000AABBCCDD");
  });
});

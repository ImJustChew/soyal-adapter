import { describe, expect, test } from "bun:test";
import {
  bypassAcknowledgement,
  bypassRecordArea,
  bypassRecordDeclaredLength,
  bypassRecordFrame,
  bypassRecordLength,
  decodeBypassRecord,
  splitBypassRecords,
} from "./bypass";
import { eventTime } from "./event";

// The worked example from SOYAL's "701ServerSQL Event Log Bypass Second Server"
// document, version 1.01. The document annotates several of its fields, and
// those annotations are what this test asserts against.
const vendorExample = [
  0x21, 0x0b, 0x01, 0x1c, 0x0d, 0x10, 0x04, 0x11, 0x01, 0x18, 0x11, 0x00, 0x01, 0x20, 0x00, 0x10,
  0x00, 0xd4, 0xef, 0x01, 0x00, 0x74, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x72, 0x71,
  0x01, 0x64, 0x01, 0x16,
];

function example(): Uint8Array {
  return new Uint8Array(vendorExample);
}

describe("701ServerSQL event log bypass records", () => {
  test("the vendor example is exactly one record long", () => {
    expect(example()).toHaveLength(bypassRecordLength);
    expect(bypassAcknowledgement).toBe(0x37);
  });

  test("decodes every field the vendor document annotates", () => {
    const event = decodeBypassRecord(example());

    // "0B (Hex) = 11 (Dec), means M11 : Normal Access"
    expect(event.functionCode).toBe(11);
    expect(event.functionDescription).toBe("normal access by tag");

    // "01 means Node ID 001"
    expect(event.sourceNode).toBe(1);

    // "28 Secs / 13 Mins / 16 Hours / Wednesday / 17 Date / Jan Month / 2024 Year"
    expect(event.second).toBe(28);
    expect(event.minute).toBe(13);
    expect(event.hour).toBe(16);
    expect(event.weekday).toBe(4);
    expect(event.day).toBe(17);
    expect(event.month).toBe(1);
    expect(event.year).toBe(24);

    // "00 01 Means User Address 000001"
    expect(event.userAddress).toBe(1);
  });

  test("recovers the site code and card code the vendor document names", () => {
    const event = decodeBypassRecord(example());
    // "D4 EF (Hex) = 54511 (Dec) means Side Code 54511"
    expect((event.tagUid[4] << 8) | event.tagUid[5]).toBe(54_511);
    // "74 A3 (Hex) = 29859 (Dec) means Card Code 29859"
    expect((event.tagUid[6] << 8) | event.tagUid[7]).toBe(29_859);
  });

  test("reads the area code from the position the vendor document gives", () => {
    // "The 100 bytes location TxBfx[92] means Area Code"
    expect(bypassRecordArea(example())).toBe(0);
    const other = example();
    other[92] = 15;
    expect(bypassRecordArea(other)).toBe(15);
  });

  test("keeps byte 0 as the declared body length, matching a 7E frame", () => {
    // A 25H frame for the same event body also declares 0x21 here.
    expect(bypassRecordDeclaredLength(example())).toBe(0x21);
  });

  test("builds a frame the shared event decoder accepts", () => {
    const frame = bypassRecordFrame(example());
    expect(frame.did).toBe(0);
    expect(frame.command).toBe(0x0b);
    expect(frame.data).toHaveLength(bypassRecordLength - 2);
  });

  test("maps the timestamp into the configured zone rather than the host zone", () => {
    const event = decodeBypassRecord(example());
    // 2024-01-17 16:13:28 in Taipei is 08:13:28Z.
    expect(eventTime(event, "Asia/Taipei").toISOString()).toBe("2024-01-17T08:13:28.000Z");
    // The same wall clock in UTC is a different instant, which is why the zone
    // must be configured rather than inherited from wherever this runs.
    expect(eventTime(event, "UTC").toISOString()).toBe("2024-01-17T16:13:28.000Z");
  });

  test("refuses a record that is not exactly 100 bytes", () => {
    expect(() => decodeBypassRecord(example().slice(0, 99))).toThrow("want exactly 100");
    expect(() => decodeBypassRecord(new Uint8Array(101))).toThrow("want exactly 100");
  });

  test("splits a stream into whole records and keeps the remainder", () => {
    const stream = new Uint8Array(bypassRecordLength * 2 + 7);
    stream.set(example(), 0);
    stream.set(example(), bypassRecordLength);
    const { records, remainder } = splitBypassRecords(stream);
    expect(records).toHaveLength(2);
    expect(remainder).toHaveLength(7);
    expect(decodeBypassRecord(records[1]).userAddress).toBe(1);
  });

  test("yields nothing until a whole record has arrived", () => {
    const partial = example().slice(0, 99);
    const { records, remainder } = splitBypassRecords(partial);
    expect(records).toHaveLength(0);
    expect(remainder).toHaveLength(99);
  });
});

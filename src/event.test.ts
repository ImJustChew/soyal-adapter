import { describe, expect, test } from "bun:test";
import { buildFrame, parseFrame } from "./frame";
import { decodeEventQueueStatus, decodeEventRecord, describeEventFunctionCode, eventRecordDataLength, eventTime } from "./event";

function eventData(): Uint8Array {
  const data = new Uint8Array(eventRecordDataLength);
  data.set([9, 1, 2, 3, 4, 5, 6, 26, 17, 0x12, 0x34, 10, 0x80, 0x9a, 0xd5, 5, 6, 7, 0, 7, 8, 3, 4, 1, 2, 0xaa, 0xbb, 0xcc, 0xdd]);
  return data;
}

describe("SOYAL event records", () => {
  test("decodes the captured AR-821EFv5 queue extensions after the nine pointer bytes", () => {
    const captures = [
      ["000687002163001ADC000000", 1671, 8547, 6876, "000000"],
      ["0001E60006E20004FC000000FFFFFF", 486, 1762, 1276, "000000FFFFFF"],
      ["007CA0002020002080000000", 31904, 8224, 8320, "000000"],
      ["000BA00021ED00164D000000FFFFFF", 2976, 8685, 5709, "000000FFFFFF"],
    ] as const;
    for (const [hex, logCounter, inputPointer, outputPointer, extension] of captures) {
      const data = new Uint8Array(hex.match(/[0-9a-f]{2}/gi)!.map((byte) => Number.parseInt(byte, 16)));
      const status = decodeEventQueueStatus(data);
      expect(status).toMatchObject({ logCounter, inputPointer, outputPointer });
      expect(Array.from(status.extension, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase()).toBe(extension);
    }
  });

  test("decodes a captured indexed 25H event record with its full 29-byte payload", () => {
    const data = new Uint8Array("0212080F030F091A11FFFF0000100000000200000000000000000004D2".match(/[0-9a-f]{2}/gi)!.map((byte) => Number.parseInt(byte, 16)));
    const event = decodeEventRecord({ did: 0, command: 0x15, data });
    expect(event).toMatchObject({ sourceNode: 2, hour: 15, doorNumber: 2, functionCode: 0x15 });
    expect(eventTime(event, "Asia/Taipei").toISOString()).toBe("2026-09-15T07:08:18.000Z");
  });

  test("keeps the live AR-821EFv5 stored source node as diagnostic data", () => {
    const data = new Uint8Array("010F070F030F091A11FFFF0000100000000100000000000000000004D2".match(/[0-9a-f]{2}/gi)!.map((byte) => Number.parseInt(byte, 16)));
    const event = decodeEventRecord({ did: 0, command: 0x0b, data });
    expect(event).toMatchObject({ sourceNode: 1, hour: 15, doorNumber: 1, functionCode: 0x0b });
  });

  test("decodes the scattered UID fields and timestamp", () => {
    const frame = parseFrame(buildFrame(0, 11, eventData()));
    const event = decodeEventRecord(frame);
    expect(event.sourceNode).toBe(9);
    expect(event.second).toBe(1);
    expect(event.port).toBe(17);
    expect(event.userAddress).toBe(0x1234);
    expect(event.subCode).toBe(10);
    expect(event.subFunction).toBe(0x80);
    expect(event.extCode).toBe(0x9a);
    expect(event.userLevel).toBe(0x15);
    expect(event.freeAccess).toBe(true);
    expect(event.multiDoorOrWg).toBe(true);
    expect(event.doorNumber).toBe(7);
    expect(Array.from(event.tagUid)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(event.tagUidUsesData21To24).toBe(true);
    expect(event.functionDescription).toContain("normal access");
    expect(eventTime(event, "Asia/Taipei").toISOString()).toBe("2026-06-04T19:02:01.000Z");
  });

  test("uses Data 9-10 for an invalid-card UID and does not use stored values", () => {
    const invalidCard = eventData();
    invalidCard[9] = 0xaa;
    invalidCard[10] = 0xbb;
    const event = decodeEventRecord({ did: 0, command: 3, data: invalidCard });
    expect(event.userAddress).toBe(0);
    expect(event.tagUid[6]).toBe(0xaa);
    expect(event.tagUid[7]).toBe(0xbb);
    const storedValue = eventData();
    storedValue[21] = 0xb5;
    storedValue[22] = 0xb6;
    storedValue[23] = 0xb7;
    storedValue[24] = 0xb8;
    const valueEvent = decodeEventRecord({ did: 0, command: 70, data: storedValue });
    expect(valueEvent.tagUidUsesData21To24).toBe(false);
    expect(Array.from(valueEvent.tagUid)).toEqual([0, 0, 0, 0, 5, 6, 7, 8]);
  });

  test("maps every specified event data position", () => {
    const data = eventData();
    data.set([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xd5, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc]);
    const event = decodeEventRecord({ did: 0, command: 11, data });
    expect(event.sourceNode).toBe(0xa0);
    expect(event.port).toBe(0xa8);
    expect(event.userAddress).toBe(0xa9aa);
    expect(event.subCode).toBe(0xab);
    expect(event.subFunction).toBe(0xac);
    expect(event.extCode).toBe(0xad);
    expect(event.userLevel).toBe(0x15);
    expect(Array.from(event.tagUid)).toEqual([0xb7, 0xb8, 0xb5, 0xb6, 0xaf, 0xb0, 0xb3, 0xb4]);
  });

  test("rejects short records and describes unknown functions", () => {
    expect(() => decodeEventRecord({ did: 0, command: 11, data: new Uint8Array(eventRecordDataLength - 1) })).toThrow();
    expect(describeEventFunctionCode(0xfe).toLowerCase()).toContain("unknown");
  });
});

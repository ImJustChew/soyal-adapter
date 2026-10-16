import { describe, expect, test } from "bun:test";
import { CommandOutcome, classifyEchoCode, decodeControllerClock, EVENT_PULL_PAGE_SIZE, SoyalAdapter } from "./adapter";
import { maximumUserRecordsPerRead } from "./command";
import { type Frame } from "./frame";
import { buildSetGuestAccessBody, encodeUserRecord, type GuestAccessRecord, type UserRecord } from "./record";
import { SoyalWireError, type SoyalWire, type WireTarget } from "./wire";

class FakeWire implements SoyalWire {
  public readonly calls: Array<{ target: WireTarget; body: Uint8Array; signal?: AbortSignal }> = [];
  private index = 0;

  public constructor(
    private readonly responses: Array<Frame | Error>,
    private readonly responseForCall?: (target: WireTarget, body: Uint8Array) => Frame | Error,
  ) {}

  public async send(target: WireTarget, body: Uint8Array, signal?: AbortSignal): Promise<Frame> {
    this.calls.push({ target, body: new Uint8Array(body), signal });
    const response = this.responseForCall?.(target, body) ?? this.responses[Math.min(this.index++, this.responses.length - 1)];
    if (response instanceof Error) throw response;
    if (!response) throw new Error("fake wire has no canned response");
    return response;
  }
}

function frame(command: number, data: number[] | Uint8Array = [], did = 0): Frame {
  return { did, command, data: data instanceof Uint8Array ? data : new Uint8Array(data) };
}

function adapter(wire: SoyalWire, config: ConstructorParameters<typeof SoyalAdapter>[0] = {}) {
  return new SoyalAdapter({ area: 0, node: 2, ...config }, wire);
}

function userReply(node: number, count: number, record: UserRecord): Frame {
  const one = encodeUserRecord(record).slice(2);
  const data = new Uint8Array(1 + count * 24);
  data[0] = node;
  for (let index = 0; index < count; index += 1) data.set(one, 1 + index * 24);
  return frame(0x03, data);
}

function emptyUserReply(node: number, count: number): Frame {
  return userReply(node, count, {
    userAddress: 0,
    tagUid: new Uint8Array(8),
    pinCode: 0,
    mode: 0,
    zone: 0,
    group1: 0,
    group2: 0,
    year: 0,
    month: 0,
    day: 0,
    level: 0,
    option: 0,
    reserved: new Uint8Array(3),
  });
}

function clockReply(node: number, second: number, minute: number, hour: number): Frame {
  return frame(0x03, [node, second, minute, hour, 0, 14, 3, 26]);
}

function eventReply(sourceNode = 2): Frame {
  const data = new Uint8Array(29);
  data[0] = sourceNode;
  data[1] = 30;
  data[2] = 45;
  data[3] = 13;
  data[5] = 14;
  data[6] = 3;
  data[7] = 26;
  data[15] = 0x57;
  data[16] = 0xb2;
  data[17] = 2;
  data[19] = 0x35;
  return frame(0x0b, data);
}

function hexBytes(value: string): Uint8Array {
  return new Uint8Array(value.match(/[0-9a-f]{2}/gi)!.map((byte) => Number.parseInt(byte, 16)));
}

describe("SoyalAdapter direct wire", () => {
  test("rejects controller node and range values outside the SOYAL protocol", () => {
    const wire = new FakeWire([frame(0x04)]);
    expect(() => new SoyalAdapter({ node: 0 }, wire)).toThrow("node must be an integer from 1 through 254");
    expect(() => new SoyalAdapter({ nodeStart: 3, nodeEnd: 2 }, wire)).toThrow("nodeEnd must not be less than nodeStart");
  });

  test("classifies the controller echo byte, including every defined failure code", () => {
    expect(classifyEchoCode(0x03).outcome).toBe(CommandOutcome.OK);
    expect(classifyEchoCode(0x04).outcome).toBe(CommandOutcome.OK);
    for (const code of [0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e]) {
      expect(classifyEchoCode(code)).toMatchObject({ outcome: CommandOutcome.Rejected, code: "device_rejected" });
    }
    expect(classifyEchoCode(0x02)).toMatchObject({ outcome: CommandOutcome.Failed, code: "invalid_frame" });
  });

  test("uses the returned echo code for write acknowledgement", async () => {
    const wire = new FakeWire([frame(0x04)]);
    const result = await adapter(wire).writeCredential({ address: 42, desired: { tagUid: "57:B2:35", doorNumbers: [1, 16] } });
    expect(result).toMatchObject({ outcome: CommandOutcome.OK, data: { address: 42, mode: "84H" } });
    expect(wire.calls[0]).toMatchObject({ target: { area: 0, node: 2 } });
    expect(Array.from(wire.calls[0]!.body.slice(0, 14))).toEqual([0x84, 0x01, 0x00, 0x2a, 0, 0, 0, 0, 0, 0x57, 0xb2, 0x35, 0, 0]);
  });

  test("writes an open-ended 84H record with the site's working never-expires convention, not an all-zero date", async () => {
    // See the comment on writeUserCredential in adapter.ts: a record with an
    // all-zero expiry date and fingerprintOmittedAfterCard clear read back as
    // a byte-perfect echo of what was written, but this site's controllers
    // silently denied it with no event logged. Every one of this site's own
    // pre-existing cards instead carries 2079-12-31 and that mode bit set,
    // even with the expiry-check bit off, and matching that byte-for-byte is
    // what actually opens the door.
    const wire = new FakeWire([frame(0x04)]);
    await adapter(wire).writeCredential({ address: 42, desired: { tagUid: "57:B2:35", doorNumbers: [1, 16] } });
    const body = wire.calls[0]!.body;
    // mode(16), zone(17), group1(18), group2(19), year(20), month(21), day(22)
    expect(body[16]).toBe(0x48); // CardOnly (0x40) | fingerprintOmittedAfterCard (0x08)
    expect(body[20]).toBe(79);
    expect(body[21]).toBe(12);
    expect(body[22]).toBe(31);
  });

  test("does not treat a controller data echo as a successful write", async () => {
    const result = await adapter(new FakeWire([frame(0x03, new Uint8Array(24))])).writeCredential({ address: 42, desired: { tagUid: "57:B2:35", doorNumbers: [1] } });
    expect(result).toMatchObject({ outcome: CommandOutcome.Rejected, detail: "controller returned echo 0x03 (request data), not write ACK 0x04" });
  });

  test("maps a controller NACK to a rejected result without server-envelope handling", async () => {
    const result = await adapter(new FakeWire([frame(0x05)])).deleteCredential({ address: 42 });
    expect(result).toMatchObject({ outcome: CommandOutcome.Rejected, code: "device_rejected" });
  });

  test("maps a direct wire failure to a failed transport result", async () => {
    const result = await adapter(new FakeWire([new SoyalWireError("controller timed out", "timeout")])).readCredential({ address: 42 });
    expect(result).toMatchObject({ outcome: CommandOutcome.Failed, code: "transport_error", detail: "controller timed out" });
  });

  test("does not send a locally invalid credential", async () => {
    const wire = new FakeWire([frame(0x04)]);
    const result = await adapter(wire).writeCredential({ address: 42, desired: { tagUid: "not-hex", doorNumbers: [1] } });
    expect(result).toMatchObject({ outcome: CommandOutcome.Failed, code: "invalid_request" });
    expect(wire.calls).toHaveLength(0);
  });

  test("reads a four-record 87H window, validates the source node, and preserves big-endian UID data", async () => {
    const record: UserRecord = {
      userAddress: 42,
      tagUid: new Uint8Array([0, 0, 0, 0, 0, 0, 0x12, 0x34]),
      pinCode: 0,
      mode: 0x04,
      zone: 0,
      group1: 1,
      group2: 0x81,
      year: 26,
      month: 3,
      day: 14,
      level: 0,
      option: 0,
      reserved: new Uint8Array(3),
    };
    const wire = new FakeWire([userReply(2, 4, record)]);
    const result = await adapter(wire).readCredential({ address: 42 });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data).toMatchObject({ address: 42, tagUid: "0000000000001234", doors: [1, 8, 9], validUntil: new Date(2026, 2, 14, 23, 59, 59) });
    expect(result.data?.actualHash).toMatch(/^[0-9a-f]{64}$/);
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x87, 0x00, 0x2a, 0x04]);
  });

  test("keeps the requested address inside the window at the top of the address space", async () => {
    const wire = new FakeWire([emptyUserReply(2, 4)]);
    const result = await adapter(wire).readCredential({ address: 16383 });
    expect(result).toMatchObject({ outcome: CommandOutcome.OK, data: { address: 16383 } });
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x87, 0x3f, 0xfc, 0x04]);
  });

  // A credential read is exactly the case direct-IP addressing must NOT relax:
  // silently stripping a mismatched prefix here would decode a shifted,
  // wrong tag/door-access record as if it were valid. See the queue-status
  // regression test below and controllerPayload's own comment for why only
  // individual 25H event records (which carry their own embedded, benign
  // self-identity byte, checked nowhere by controllerPayload) get relaxed.
  test("rejects a direct response whose stored source-node prefix differs from the requested node", async () => {
    const wire = new FakeWire([userReply(3, 4, {
      userAddress: 42,
      tagUid: new Uint8Array(8),
      pinCode: 0,
      mode: 0,
      zone: 0,
      group1: 0,
      group2: 0,
      year: 0,
      month: 0,
      day: 0,
      level: 0,
      option: 0,
      reserved: new Uint8Array(3),
    })]);
    const result = await adapter(wire).readCredential({ address: 42 });
    expect(result.outcome).toBe(CommandOutcome.Failed);
    expect(result.detail).toBe("87H response carries data from node 3 but the request was sent to node 2");
  });

  test("keeps page size behavior for an 87H page", async () => {
    const wire = new FakeWire([emptyUserReply(2, 2)]);
    const instance = adapter(wire);
    instance.pageSize = 2;
    const result = await instance.listCredentials({ addressStart: 0, addressEnd: 1 });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(wire.calls).toHaveLength(1);
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x87, 0, 0, 2]);
  });

  test("does not exceed the standard-frame user-record limit", async () => {
    const wire = new FakeWire([emptyUserReply(2, maximumUserRecordsPerRead)]);
    const instance = adapter(wire);
    instance.pageSize = maximumUserRecordsPerRead;
    const result = await instance.listCredentials({ addressStart: 0, addressEnd: maximumUserRecordsPerRead - 1 });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x87, 0, 0, maximumUserRecordsPerRead]);
  });

  test("uses one 8BH read request per guest address", async () => {
    const guestRecord: GuestAccessRecord = { userAddress: 0, tagUid: new Uint8Array(8), pinCode: 0, mode: 0, zone: 0, group1: 0, group2: 0, beginYear: 0, beginMonth: 0, beginDay: 0, beginHour: 0, beginMinute: 0, endYear: 0, endMonth: 0, endDay: 0, endHour: 0, endMinute: 0, lift: new Uint8Array(4) };
    const body = buildSetGuestAccessBody(guestRecord);
    body[1] = 0x52;
    const data = new Uint8Array(1 + 34);
    data[0] = 2;
    data.set(body.slice(1), 1);
    const wire = new FakeWire([frame(0x03, data), frame(0x03, data)]);
    const instance = adapter(wire, { credentialWriteMode: "8BH" });
    instance.pageSize = 2;
    const result = await instance.listCredentials({ addressStart: 0, addressEnd: 1 });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(wire.calls).toHaveLength(2);
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x8b, 0x52, 0, 0, 0]);
    expect(Array.from(wire.calls[1]!.body)).toEqual([0x8b, 0x52, 0, 0, 1]);
  });

  test("sends a credential command to the controller named in arguments", async () => {
    const wire = new FakeWire([frame(0x04)]);
    const result = await adapter(wire).deleteCredential({ address: 42, controller: { area: 1, node: 5 } });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(wire.calls[0]).toMatchObject({ target: { area: 1, node: 5 }, body: new Uint8Array([0x85, 0, 42, 0, 42]) });
  });

  test("decodes event records from direct 25H frames", async () => {
    const status = [2, 0, 0, 1, 0, 0, 1, 0, 0, 0];
    const eventData = new Uint8Array(29);
    eventData[0] = 2;
    eventData[1] = 30;
    eventData[2] = 45;
    eventData[3] = 13;
    eventData[5] = 14;
    eventData[6] = 3;
    eventData[7] = 26;
    eventData[15] = 0x57;
    eventData[16] = 0xb2;
    eventData[17] = 2;
    eventData[19] = 0x35;
    const wire = new FakeWire([frame(0x03, status), frame(0x03, status), frame(0x0b, eventData)]);
    const result = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 } });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data?.events).toHaveLength(1);
    expect(result.data?.events[0]).toMatchObject({ kind: "event", deviceSourceNode: 2, door: 2, functionCode: 0x0b, userAddress: 0, tagUid: "0000000057B23500" });
    expect(result.data?.cursor).toBe("1");
  });

  test("pulls the captured AR-821EFv5 25H record shape when its stored source node is 1", async () => {
    const status = [4, 0, 0, 1, 0, 0, 1, 0, 0, 0];
    // This is the 29-byte live event-record shape captured from the installed
    // AR-821EFv5 family. Queue status still requires its own leading byte to
    // match the dialed node (see the queue-status regression test below); only
    // the individual event RECORD's embedded identity, decoded from its own
    // first byte inside decodeEventRecord and never checked by
    // controllerPayload, is allowed to differ. Node 4's direct socket reported
    // 0x01 there even though the request targeted database node 4.
    const eventData = hexBytes("010F070F030F091A11FFFF0000100000000100000000000000000004D2");
    const wire = new FakeWire([frame(0x03, status), frame(0x03, status), frame(0x0b, eventData)]);
    const result = await adapter(wire).pullEvents({ controller: { area: 0, node: 4 } });
    expect(result).toMatchObject({ outcome: CommandOutcome.OK, data: { cursor: "1" } });
    expect(result.data?.events[0]).toMatchObject({ controller: { area: 0, node: 4 }, deviceSourceNode: 1, door: 1 });
  });

  test("limits event pulls to one page and advances the cursor by records read", async () => {
    const pageOneStatus = [2, 0, 1, 4, 0, 1, 4, 0, 0, 0];
    const wire = new FakeWire([], (_target, body) => {
      if (body[0] === 0x25 && body[1] === 0xff && body[2] === 0xff && body[3] === 0xff) {
        return frame(0x03, pageOneStatus);
      }
      return eventReply();
    });

    const first = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 } });
    const second = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 }, cursor: first.data?.cursor });

    expect(first.outcome).toBe(CommandOutcome.OK);
    expect(first.data?.events).toHaveLength(EVENT_PULL_PAGE_SIZE);
    expect(first.data?.cursor).toBe(String(EVENT_PULL_PAGE_SIZE));
    expect(second.outcome).toBe(CommandOutcome.OK);
    expect(second.data?.events).toHaveLength(4);
    expect(second.data?.cursor).toBe("260");
    expect(wire.calls
      .filter((call) => call.body[0] === 0x25 && call.body[1] !== 0xff)
      .map((call) => (call.body[1]! << 16) | (call.body[2]! << 8) | call.body[3]!))
      .toEqual(Array.from({ length: 260 }, (_, index) => index));
  });

  test("preserves a wrapped-ring gap marker while paging the readable records", async () => {
    const wrappedStatus = [2, 0, 0, 4, 0, 0, 104, 0, 0, 100];
    const wire = new FakeWire([], (_target, body) => {
      if (body[0] === 0x25 && body[1] === 0xff && body[2] === 0xff && body[3] === 0xff) {
        return frame(0x03, wrappedStatus);
      }
      return eventReply();
    });

    const result = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 }, cursor: "90" });

    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data?.events[0]).toEqual(expect.objectContaining({ kind: "gap", reason: "log_wrapped", estimatedCount: 4 }));
    expect(result.data?.events.slice(1)).toHaveLength(4);
    expect(result.data?.cursor).toBe("104");
  });

  test("marks a wrapped ring with the estimated overwritten count when no cursor exists", async () => {
    const wrappedStatus = [2, 0, 0x7c, 0xa0, 0, 0x20, 0x20, 0, 0x20, 0x80];
    const wire = new FakeWire([], (_target, body) => {
      if (body[0] === 0x25 && body[1] === 0xff && body[2] === 0xff && body[3] === 0xff) {
        return frame(0x03, wrappedStatus);
      }
      return eventReply();
    });

    const result = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 } });

    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data?.events[0]).toEqual(expect.objectContaining({ kind: "gap", reason: "log_wrapped", estimatedCount: 96 }));
    expect(result.data?.events.slice(1)).toHaveLength(EVENT_PULL_PAGE_SIZE);
    expect(result.data?.cursor).toBe("8576");
  });

  test("wraps indexed reads and cursors at the controller ring boundary", async () => {
    const wrappedStatus = [2, 0, 1, 4, 0, 0, 160, 0, 124, 0x9c];
    const wire = new FakeWire([], (_target, body) => {
      if (body[0] === 0x25 && body[1] === 0xff && body[2] === 0xff && body[3] === 0xff) {
        return frame(0x03, wrappedStatus);
      }
      return eventReply();
    });
    const instance = adapter(wire);

    const first = await instance.pullEvents({ controller: { area: 0, node: 2 } });
    const second = await instance.pullEvents({ controller: { area: 0, node: 2 }, cursor: first.data?.cursor });

    expect(first.data?.cursor).toBe("156");
    expect(first.data?.events.slice(1)).toHaveLength(EVENT_PULL_PAGE_SIZE);
    expect(second.data?.cursor).toBe("160");
    expect(second.data?.events).toHaveLength(4);
    expect(wire.calls
      .filter((call) => call.body[0] === 0x25 && call.body[1] !== 0xff)
      .map((call) => (call.body[1]! << 16) | (call.body[2]! << 8) | call.body[3]!))
      .toEqual([...Array.from({ length: 100 }, (_, index) => 31_900 + index), ...Array.from({ length: 160 }, (_, index) => index)]);
  });

  test("recovers a zero-depth event queue whose pointer moves when indexed records are readable", async () => {
    const emptyAtZero = frame(0x03, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const emptyAtTwo = frame(0x03, [2, 0, 0, 0, 0, 0, 2, 0, 0, 2]);
    const wire = new FakeWire([emptyAtZero, emptyAtZero, emptyAtTwo, emptyAtTwo, eventReply(), eventReply()]);
    const first = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 } });
    expect(first).toMatchObject({ outcome: CommandOutcome.OK, data: { cursor: "0", events: [] } });

    const second = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 }, cursor: first.data?.cursor });
    expect(second).toMatchObject({ outcome: CommandOutcome.OK, data: { cursor: "2" } });
    expect(second.data?.events).toHaveLength(2);
    expect(second.data?.events.every((event) => event.kind === "event")).toBe(true);
    expect(wire.calls.slice(4).map((call) => Array.from(call.body))).toEqual([[0x25, 0, 0, 0], [0x25, 0, 0, 1]]);
  });

  test("refuses a zero-depth pointer move when an indexed record cannot be read", async () => {
    const emptyAtZero = frame(0x03, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const emptyAtTwo = frame(0x03, [2, 0, 0, 0, 0, 0, 2, 0, 0, 2]);
    const wire = new FakeWire([emptyAtZero, emptyAtZero, emptyAtTwo, emptyAtTwo, eventReply(), frame(0x05)]);
    const first = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 } });
    expect(first.outcome).toBe(CommandOutcome.OK);

    const second = await adapter(wire).pullEvents({ controller: { area: 0, node: 2 }, cursor: first.data?.cursor });
    expect(second.outcome).toBe(CommandOutcome.Failed);
    expect(second.code).toBe("pointer_ahead_unconfirmed");
    expect(second.detail).toBe("25H queue pointer changed from 0 to 2 while queue depth was zero, and reading the individual records also failed");
    expect(second.data as unknown).toEqual({ previousCursor: 0, observedPointer: 2 });
    expect(wire.calls).toHaveLength(6);
  });

  test("refuses queue-status samples that are not stable across reads", async () => {
    const firstStatus = frame(0x03, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const changedStatus = frame(0x03, [2, 0, 0, 0, 0, 0, 1, 0, 0, 1]);
    const result = await adapter(new FakeWire([firstStatus, changedStatus])).pullEvents({ controller: { area: 0, node: 2 } });
    expect(result).toMatchObject({
      outcome: CommandOutcome.Failed,
      code: "invalid_record",
      detail: "25H queue status was not stable across two reads; cursor was not advanced",
    });
  });

  // Regression for the live incident on 2026-09-16: a queue-status reply
  // whose leading byte does not match the dialed node must be rejected, not
  // silently stripped as if it were a benign event-record identity quirk.
  // Stripping it there shifted every counter byte and decoded a stable but
  // enormous fake input pointer, which the (correctly bounded) wrap logic
  // then chased forever, fabricating thousands of huge "gap" rows in prod.
  test("rejects a queue-status reply whose leading byte does not match the dialed node", async () => {
    const wrongNodeStatus = frame(0x03, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const result = await adapter(new FakeWire([wrongNodeStatus, wrongNodeStatus])).pullEvents({ controller: { area: 0, node: 2 } });
    expect(result.outcome).toBe(CommandOutcome.Failed);
    expect(result.detail).toBe("25H queue status carries data from node 1 but the request was sent to node 2");
  });

  test("returns unsupported when a capability is narrowed", async () => {
    const wire = new FakeWire([]);
    const result = await adapter(wire, { capabilities: ["readCredential"] }).deleteCredential({ address: 42 });
    expect(result).toEqual({
      outcome: CommandOutcome.Unsupported,
      code: "capability_unsupported",
      detail: "SOYAL site does not support deleteCredential",
    });
    expect(wire.calls).toHaveLength(0);
  });

  test("writes 84H user records by default and uses 8BH only when guest records are configured", async () => {
    const userWire = new FakeWire([frame(0x04)]);
    const userResult = await adapter(userWire).writeCredential({ address: 42, desired: { tagUid: "57:B2:35", doorNumbers: [1] } });
    expect(userResult).toMatchObject({ outcome: CommandOutcome.OK, data: { address: 42, mode: "84H" } });
    expect(Array.from(userWire.calls[0]!.body.slice(0, 4))).toEqual([0x84, 0x01, 0x00, 0x2a]);

    const guestWire = new FakeWire([frame(0x04)]);
    const guestResult = await adapter(guestWire, { credentialWriteMode: "8BH" }).writeCredential({ address: 42, desired: { tagUid: "57:B2:35", doorNumbers: [1] } });
    expect(guestResult).toMatchObject({ outcome: CommandOutcome.OK, data: { address: 42, mode: "8BH" } });
    expect(Array.from(guestWire.calls[0]!.body.slice(0, 5))).toEqual([0x8b, 0x57, 0x00, 0x00, 0x2a]);
  });

  test("returns unsupported for door control until the unsourced 21H candidate is hardware-validated", async () => {
    const result = await adapter(new FakeWire([])).controlDoor({ door: 1 });
    expect(result).toEqual({ outcome: CommandOutcome.Unsupported, code: "command_unsupported" });
  });

  test("discovers only the caller-provided controllers by probing 12H identity", async () => {
    const wire = new FakeWire([], (target) => target.node === 2
      ? frame(0x03, [2, 0, 1, ...Array.from({ length: 12 }, (_, index) => index + 1)])
      : new SoyalWireError("offline", "connection"));
    const result = await adapter(wire).discover({ controllers: [{ area: 0, node: 2 }, { area: 0, node: 3 }] });
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data?.controllers[0]).toMatchObject({ area: 0, node: 2, online: true });
    expect(result.data?.controllers[1]).toEqual({ area: 0, node: 3, online: false });
    expect(wire.calls).toHaveLength(2);
    expect(Array.from(wire.calls[0]!.body)).toEqual([0x12, 0xfe]);
  });

  test("keeps controllerStatus and clock probes but rejects removed serverInfo", async () => {
    const wire = new FakeWire([clockReply(2, 30, 45, 13)]);
    const clock = await adapter(wire).probe({ probe: "clock", controller: { area: 0, node: 2 } });
    expect(clock.outcome).toBe(CommandOutcome.OK);
    expect((clock.data as { controllerTime: Date }).controllerTime).toEqual(new Date(2026, 2, 14, 13, 45, 30));

    const statusWire = new FakeWire([frame(0x03, [2, 0, 1, ...Array.from({ length: 12 }, (_, index) => index + 1)])]);
    const status = await adapter(statusWire).probe({ probe: "controllerStatus", controllers: [{ area: 0, node: 2 }] });
    expect(status).toMatchObject({ outcome: CommandOutcome.OK, data: { probe: "controllerStatus", controllers: [{ node: 2, online: true }] } });

    const removed = await adapter(new FakeWire([])).probe({ probe: "serverInfo" });
    expect(removed).toMatchObject({ outcome: CommandOutcome.Failed, code: "invalid_request" });
  });

  test("reads one 24H clock frame per controller in a batch", async () => {
    const wire = new FakeWire([], (target) => target.node === 2
      ? clockReply(2, 30, 45, 13)
      : clockReply(3, 10, 20, 9));
    const result = await adapter(wire).readClockBatch([{ area: 0, node: 2 }, { area: 0, node: 3 }]);
    expect(result.outcome).toBe(CommandOutcome.OK);
    expect(result.data?.readings).toHaveLength(2);
    expect(result.data?.readings[0]).toMatchObject({ area: 0, node: 2, controllerTime: new Date(2026, 2, 14, 13, 45, 30) });
    expect(result.data?.readings[1]).toMatchObject({ area: 0, node: 3, controllerTime: new Date(2026, 2, 14, 9, 20, 10) });
    expect(wire.calls).toHaveLength(2);
    expect(wire.calls.every((call) => Array.from(call.body).join(",") === "36")).toBe(true);
  });

  test("retains direct commissioning parameter reads and decodes their fingerprints", async () => {
    const serial = [2, 0x01, 0x02, ...Array.from({ length: 12 }, (_, index) => index + 1)];
    const network = new Uint8Array(32);
    network[0] = 2;
    network[1] = 0;
    network[2] = 0;
    network[3] = 0x11;
    network[4] = 0x22;
    network[5] = 0x33;
    network[6] = 0x44;
    network[7] = 0x55;
    network.set([192, 168, 0, 2], 8);
    network[27] = 0x06;
    network[28] = 0x55;
    const mode = new Uint8Array(51);
    mode[0] = 2;
    mode[50] = 0;
    const available = [2, 0x40];
    const wire = new FakeWire([
      frame(0x03, serial),
      frame(0x03, network),
      frame(0x03, mode),
      frame(0x03, available),
      clockReply(2, 30, 45, 13),
    ]);
    const result = await adapter(wire).commission({ controller: { area: 0, node: 2 } });
    expect(result).toMatchObject({ outcome: CommandOutcome.OK, data: { serial: "0102030405060708090A0B0C", ip: "192.168.0.2", mac: "00:11:22:33:44:55", capacityMode: 16384, availableUsers: 64 } });
    expect(wire.calls.map((call) => Array.from(call.body))).toEqual([[0x12, 0xfe], [0x12, 0x14], [0x12, 0x00], [0x12, 0x15], [0x24]]);
  });

  test("recognizes the captured AR-821EFv5 0x03 mode without inventing its capacity", async () => {
    const serial = [5, 0x01, 0x02, ...Array.from({ length: 12 }, (_, index) => index + 1)];
    const network = new Uint8Array(32);
    network[0] = 5;
    network.set([0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 192, 168, 0, 5], 1);
    const liveNode5Mode = hexBytes("05C301010001E240000000000000000004D204D200000104006402BC02BC05DC101001110F0F000800010103580905000000030300");
    expect(liveNode5Mode.length).toBe(53);
    expect(liveNode5Mode[50]).toBe(0x03);
    const available = [5, 0x40];
    const wire = new FakeWire([
      frame(0x03, serial),
      frame(0x03, network),
      frame(0x03, liveNode5Mode),
      frame(0x03, available),
      clockReply(5, 30, 45, 15),
    ]);
    const result = await adapter(wire, { node: 5, controllerTimezone: "Asia/Taipei" }).commission({ controller: { area: 0, node: 5 } });
    expect(result).toMatchObject({
      outcome: CommandOutcome.OK,
      data: { capacityMode: null, capacityModeCode: 0x03, availableUsers: 64 },
    });
  });

  test("interprets captured Taipei 0x0f and UTC 0x07 clock bytes against one server instant", () => {
    const serverInstant = new Date("2026-09-15T07:00:00.000Z");
    const taipei = decodeControllerClock(new Uint8Array([0, 0, 0x0f, 3, 15, 9, 26]), "Asia/Taipei");
    const node4 = decodeControllerClock(new Uint8Array([0, 0, 0x07, 3, 15, 9, 26]), "Asia/Taipei");
    expect(taipei.getTime()).toBe(serverInstant.getTime());
    expect(node4.toISOString()).toBe("2026-09-14T23:00:00.000Z");
    expect(Math.abs(taipei.getTime() - serverInstant.getTime())).toBeLessThanOrEqual(60_000);
    expect(Math.abs(node4.getTime() - serverInstant.getTime())).toBe(8 * 60 * 60 * 1000);
  });
});

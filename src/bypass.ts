import { decodeEventRecord, type EventRecord } from "./event";
import type { Frame } from "./frame";

// 701ServerSQL's event-log bypass sends each event as a fixed 100-byte record
// and waits for a single 0x37 byte before sending the next one. See
// docs/soyal-protocol-reference.md.
export const bypassRecordLength = 100;

// The byte the second server must send back to acknowledge one record. This is
// flow control on the bypass socket. It is NOT the 37H controller command that
// removes the oldest log, and it deletes nothing.
export const bypassAcknowledgement = 0x37;

// Offset of the area code within the record. The vendor names this position as
// TxBfx[92] and gives no field between the event body and it.
const areaCodeOffset = 92;

// The record is the same event body the indexed 25H read returns, delivered raw
// and padded rather than wrapped in a 7E frame:
//
//   21 0B 01 1C 0D 10 04 11 01 18 ...    bypass record
//   7E 21 00 10 02 07 0C 15 07 1D 08 1A  a 25H frame
//      len fn node sec min hour ...
//
// Byte 0 is the length indicator, byte 1 the function code, and everything from
// byte 2 on is what decodeEventRecord already understands. Checked field by
// field against the worked example in the vendor's bypass document: node 001,
// 28 seconds, 13 minutes, 16 hours, user address 1, site code D4EF and card
// code 74A3 all land where that document says they should.
export function bypassRecordFrame(record: Uint8Array): Frame {
  if (record.length !== bypassRecordLength) {
    throw new Error(`cannot read SOYAL bypass record: got ${record.length} bytes, want exactly ${bypassRecordLength}`);
  }
  return { did: 0, command: record[1], data: record.slice(2) };
}

export function decodeBypassRecord(record: Uint8Array): EventRecord {
  return decodeEventRecord(bypassRecordFrame(record));
}

export function bypassRecordArea(record: Uint8Array): number {
  if (record.length !== bypassRecordLength) {
    throw new Error(`cannot read SOYAL bypass record area: got ${record.length} bytes, want exactly ${bypassRecordLength}`);
  }
  return record[areaCodeOffset];
}

// The declared body length in byte 0. Present for diagnostics: the vendor pads
// every record to 100 bytes regardless, so this is not a framing length.
export function bypassRecordDeclaredLength(record: Uint8Array): number {
  if (record.length !== bypassRecordLength) {
    throw new Error(`cannot read SOYAL bypass record length: got ${record.length} bytes, want exactly ${bypassRecordLength}`);
  }
  return record[0];
}

// Split a stream buffer into whole records. 701ServerSQL sends one record at a
// time and waits for an acknowledgement, but TCP can still split or coalesce
// them, so never assume one read is one record.
export function splitBypassRecords(buffer: Uint8Array): { records: Uint8Array[]; remainder: Uint8Array } {
  const records: Uint8Array[] = [];
  let offset = 0;
  while (buffer.length - offset >= bypassRecordLength) {
    records.push(buffer.slice(offset, offset + bypassRecordLength));
    offset += bypassRecordLength;
  }
  return { records, remainder: buffer.slice(offset) };
}

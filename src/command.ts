import type { UserRecord } from "./record";
import { encodeUserRecord } from "./record";
import { standardFrameDataLimit } from "./frame";
import { userRecordLength24 } from "./record";
import { controllerWallClockFields } from "./timezone";

export const maximumUserAddress = 16383;

// An 87H reply carries one 24-byte record per requested address, preceded by a
// source-node byte. The protocol document gives the standard 7E frame a data
// field of 0~240 bytes, so nine records is the most that can come back.
//
// Live controllers do not enforce this themselves. Asked for ten they answer
// with a 241-byte frame that their own specification forbids, and asked for
// twelve they fail with "Error Code:-1". Refuse the request here so the caller
// gets a useful error instead of an unparseable reply.
export const maximumUserRecordsPerRead = Math.floor((standardFrameDataLimit - 1) / userRecordLength24);

export function buildReadUserBody(startAddress: number, count: number): Uint8Array {
  if (!Number.isInteger(count) || count <= 0 || count > 255) {
    throw new Error("cannot build SOYAL 87H body: count must be greater than zero and fit in one byte");
  }
  if (count > maximumUserRecordsPerRead) {
    throw new Error(`cannot build SOYAL 87H body: count ${count} needs ${count * userRecordLength24 + 1} data bytes, and a standard frame carries at most ${standardFrameDataLimit}. Request at most ${maximumUserRecordsPerRead} records.`);
  }
  validateUserAddress(startAddress, "start address");
  const lastAddress = startAddress + count - 1;
  if (lastAddress > maximumUserAddress) {
    throw new Error(`cannot build SOYAL 87H body: end address ${lastAddress} exceeds the maximum address ${maximumUserAddress}`);
  }
  return new Uint8Array([0x87, startAddress >> 8, startAddress & 0xff, count]);
}

export function buildReadUserAliasBody(startIndex: number, count: number): Uint8Array {
  if (!Number.isInteger(startIndex) || startIndex < 0 || startIndex > 0xffffff) {
    throw new Error("cannot build SOYAL 2EH body: start index must fit in three bytes");
  }
  if (!Number.isInteger(count) || count <= 0 || count > 255) {
    throw new Error("cannot build SOYAL 2EH body: count must be greater than zero and fit in one byte");
  }
  return new Uint8Array([0x2e, startIndex >> 16, startIndex >> 8, startIndex, count]);
}

export function buildSetUserBody(record: UserRecord): Uint8Array {
  validateUserAddress(record.userAddress, "user address");
  const encoded = encodeUserRecord(record);
  const body = new Uint8Array(2 + encoded.length);
  body[0] = 0x84;
  body[1] = 1;
  body.set(encoded, 2);
  return body;
}

export function buildEraseUserRangeBody(startAddress: number, endAddress: number): Uint8Array {
  if (endAddress < startAddress) {
    throw new Error(`cannot build SOYAL 85H body: end address ${endAddress} is before start address ${startAddress}`);
  }
  validateUserAddress(startAddress, "start address");
  validateUserAddress(endAddress, "end address");
  const span = endAddress - startAddress + 1;
  if (span >= 1000) {
    throw new Error(`cannot build SOYAL 85H body: erase range contains ${span} addresses; it must erase fewer than 1000`);
  }
  return new Uint8Array([0x85, startAddress >> 8, startAddress & 0xff, endAddress >> 8, endAddress & 0xff]);
}

export function buildOldestEventLogBody(): Uint8Array {
  return new Uint8Array([0x25]);
}

export function buildEventLogQueueStatusBody(): Uint8Array {
  return new Uint8Array([0x25, 0xff, 0xff, 0xff]);
}

export function buildEventLogRecordBody(index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index > 0xffffff) {
    throw new Error(`cannot build SOYAL 25H body: event log index ${index} does not fit in a 24-bit index`);
  }
  return new Uint8Array([0x25, index >> 16, index >> 8, index]);
}

export function buildReadClockBody(): Uint8Array {
  return new Uint8Array([0x24]);
}

export function buildSetClockBody(controllerTime: Date, timeZone?: string): Uint8Array {
  const fields = controllerWallClockFields(controllerTime, timeZone);
  const year = fields.year;
  if (year < 2000 || year > 2099) {
    throw new Error("controller clock year must be from 2000 through 2099 for the protocol's two-digit year field");
  }
  return new Uint8Array([
    0x23,
    fields.second,
    fields.minute,
    fields.hour,
    new Date(Date.UTC(fields.year, fields.month - 1, fields.day)).getUTCDay() + 1,
    fields.day,
    fields.month,
    year - 2000,
  ]);
}

export function buildHostingPollBody(): Uint8Array {
  return new Uint8Array([0x18]);
}

export function buildGetParameterBody(subCode: number): Uint8Array {
  if (!Number.isInteger(subCode) || subCode < 0 || subCode > 255) {
    throw new Error("SOYAL 12H parameter sub-code must fit in one byte");
  }
  return new Uint8Array([0x12, subCode]);
}

function validateUserAddress(address: number, fieldName: string): void {
  if (!Number.isInteger(address) || address < 0 || address > maximumUserAddress) {
    throw new Error(`cannot use SOYAL ${fieldName} ${address}: 2-byte user addresses are limited to 0 through ${maximumUserAddress}`);
  }
}

// 37H remove-oldest-log and 2DH empty-log builders are intentionally absent:
// both commands are irreversible and would destroy 701Client's view of the log.

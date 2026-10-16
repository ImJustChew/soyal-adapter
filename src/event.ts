import type { Frame } from "./frame";
import { controllerWallClockToDate } from "./timezone";

export const eventRecordDataLength = 29;
export const eventQueueStatusDataLength = 9;

export interface EventQueueStatus {
  logCounter: number;
  inputPointer: number;
  outputPointer: number;
  /** Model-specific bytes following the three documented 24-bit fields. */
  extension: Uint8Array;
}

/**
 * Decode 25H FF FF FF status replies. The captured AR-821EFv5 replies had
 * 12 or 15 data bytes: the first nine are the three 24-bit queue fields,
 * followed by model-specific extension bytes.
 */
export function decodeEventQueueStatus(data: Uint8Array): EventQueueStatus {
  if (data.length < eventQueueStatusDataLength) {
    throw new Error(`cannot decode SOYAL event queue status: data has ${data.length} bytes, need at least ${eventQueueStatusDataLength}`);
  }
  return {
    logCounter: decode24Bit(data, 0),
    inputPointer: decode24Bit(data, 3),
    outputPointer: decode24Bit(data, 6),
    extension: data.slice(eventQueueStatusDataLength),
  };
}

export interface EventRecord {
  sourceNode: number;
  second: number;
  minute: number;
  hour: number;
  weekday: number;
  day: number;
  month: number;
  year: number;
  port: number;
  userAddress: number;
  tagUid: Uint8Array;
  subCode: number;
  subFunction: number;
  extCode: number;
  userLevel: number;
  freeAccess: boolean;
  multiDoorOrWg: boolean;
  doorNumber: number;
  functionCode: number;
  tagUidUsesData21To24: boolean;
  functionDescription: string;
}

export function decodeEventRecord(frame: Frame): EventRecord {
  if (frame.did !== 0) {
    throw new Error(`cannot decode SOYAL event record: DID is 0x${formatByte(frame.did)}, want 0x00`);
  }
  if (frame.data.length < eventRecordDataLength) {
    throw new Error(`cannot decode SOYAL event record: data has ${frame.data.length} bytes, need at least ${eventRecordDataLength}`);
  }
  const data = frame.data;
  const tagUid = new Uint8Array(8);
  const event: EventRecord = {
    sourceNode: data[0],
    second: data[1],
    minute: data[2],
    hour: data[3],
    weekday: data[4],
    day: data[5],
    month: data[6],
    year: data[7],
    port: data[8],
    userAddress: frame.command === 3 ? 0 : (data[9] << 8) | data[10],
    tagUid,
    subCode: data[11],
    subFunction: data[12],
    extCode: data[13],
    userLevel: data[14] & 0x3f,
    freeAccess: (data[14] & 0x40) !== 0,
    multiDoorOrWg: (data[14] & 0x80) !== 0,
    doorNumber: data[17],
    functionCode: frame.command,
    tagUidUsesData21To24: !isStoredValueEvent(frame.command),
    functionDescription: describeEventFunctionCode(frame.command),
  };
  if (frame.command === 3) {
    tagUid[6] = data[9];
    tagUid[7] = data[10];
  } else {
    tagUid[6] = data[19];
    tagUid[7] = data[20];
  }
  if (event.tagUidUsesData21To24) {
    tagUid[0] = data[23];
    tagUid[1] = data[24];
    tagUid[2] = data[21];
    tagUid[3] = data[22];
  }
  tagUid[4] = data[15];
  tagUid[5] = data[16];
  return event;
}

export function eventTime(event: EventRecord, timeZone?: string): Date {
  return controllerWallClockToDate({
    year: 2000 + event.year,
    month: event.month,
    day: event.day,
    hour: event.hour,
    minute: event.minute,
    second: event.second,
  }, timeZone);
}

const eventFunctionDescriptions: Readonly<Record<number, string>> = {
  0: "site code error",
  1: "invalid user PIN",
  2: "keypad locked",
  3: "invalid card",
  4: "time zone error",
  5: "door group error",
  6: "expiry date",
  7: "over access times",
  8: "PIN code error",
  9: "duress PB",
  10: "access by card and PIN",
  11: "normal access by tag",
  12: "force relay ON",
  13: "force relay OFF",
  14: "controller armed",
  15: "controller disarmed",
  16: "button open",
  17: "alarm event",
  20: "power off",
  // The site confirmed this is the duress PIN, which staff currently use as
  // their ordinary way to open these doors. That is why it is roughly half of
  // all traffic and pairs one-for-one with code 16 button open, and why its
  // frames carry no user and no tag: a PIN entry has no card. An earlier
  // reading of those same facts concluded it could not be duress; the vendor's
  // hosting-protocol table was right and that inference was wrong.
  21: "duress PIN",
  22: "guards for help",
  23: "cleaner access",
  24: "power on",
  25: "force relay error",
  26: "reader RTN",
  27: "help button",
  28: "access by PIN",
  29: "digital input active",
  31: "RS485 reader offline",
  32: "RS485 reader online",
  33: "user PIN changed",
  34: "change PIN error",
  35: "enter auto-open",
  36: "exit auto-open",
  37: "auto disarmed",
  38: "auto armed",
  39: "access by fingerprint",
  40: "fingerprint failed",
  42: "remote up key",
  43: "disable reader",
  44: "enable reader",
  45: "remote panic key",
  46: "parking entrance",
  47: "parking exit",
  48: "parking counter",
  49: "latch relay",
  53: "enter/exit edit mode",
  55: "free access mode",
  56: "fingerprint error",
  59: "access inhibit",
  60: "never open after access",
  62: "mifare date/time read failed",
  63: "mifare command read failed",
  64: "mifare deduct failed",
  65: "SOR global card",
  66: "SOR disturber layer error",
  67: "access rejected: before begin date",
  68: "access rejected: expiry",
  69: "access rejected: value not enough",
  70: "access ok, value deducted",
  71: "access ok, lift data read failed",
  72: "SOR global variant 72",
  73: "SOR global variant 73",
  74: "SOR global variant 74",
  75: "SOR global variant 75",
};

export function describeEventFunctionCode(functionCode: number): string {
  return eventFunctionDescriptions[functionCode]
    ?? `unknown event function code 0x${formatByte(functionCode)} (${functionCode})`;
}

function isStoredValueEvent(functionCode: number): boolean {
  return functionCode >= 64 && functionCode <= 75;
}

function formatByte(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

function decode24Bit(data: Uint8Array, offset: number): number {
  return (data[offset]! << 16) | (data[offset + 1]! << 8) | data[offset + 2]!;
}

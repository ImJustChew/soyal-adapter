export const userRecordLength26 = 26;
export const userRecordLength24 = 24;
export const guestAccessBodyLength = 35;
export const guestAccessPayloadLength = guestAccessBodyLength - 1;
export const guestAccessRecordLength = 30;
export const userAliasLength = 16;

export enum AccessMode {
  Invalid = 0,
  CardOnly = 1,
  CardOrPin = 2,
  CardAndPin = 3,
}

export interface ModeFlags {
  accessMode: AccessMode;
  patrol: boolean;
  cardOmittedAfterFingerprint: boolean;
  fingerprintOmittedAfterCard: boolean;
  enableExpireCheck: boolean;
  guest: boolean;
  passwordChangeAllowed: boolean;
}

export interface GuestAccessModeFlags {
  accessMode: AccessMode;
  patrol: boolean;
  cardOmittedAfterFingerprint: boolean;
  fingerprintOmittedAfterCard: boolean;
  enableExpireCheck: boolean;
  checkBeginAndEndTime: boolean;
  passwordChangeAllowed: boolean;
}

export interface UserRecord {
  userAddress: number;
  tagUid: Uint8Array;
  pinCode: number;
  mode: number;
  zone: number;
  group1: number;
  group2: number;
  year: number;
  month: number;
  day: number;
  level: number;
  option: number;
  reserved: Uint8Array;
}

export interface GuestAccessRecord {
  userAddress: number;
  tagUid: Uint8Array;
  pinCode: number;
  mode: number;
  zone: number;
  group1: number;
  group2: number;
  beginYear: number;
  beginMonth: number;
  beginDay: number;
  beginHour: number;
  beginMinute: number;
  endYear: number;
  endMonth: number;
  endDay: number;
  endHour: number;
  endMinute: number;
  lift: Uint8Array;
}

export interface DoorBitmap {
  group1: number;
  group2: number;
}

export function encodeUserRecord(record: UserRecord): Uint8Array {
  if ((record.zone & 0x40) !== 0) {
    throw new Error("cannot encode SOYAL user record: Zone reserved bit 6 must be zero");
  }
  const encoded = new Uint8Array(userRecordLength26);
  // The protocol table calls these fields little endian, but section 2.25
  // defines its first UID byte as bits 63-56. The reference implementation
  // and the 85H/87H tables therefore all use high byte first here.
  encoded[0] = record.userAddress >> 8;
  encoded[1] = record.userAddress & 0xff;
  encoded.set(normalizeBytes(record.tagUid, 8), 2);
  writeUint32(encoded, 10, record.pinCode);
  encoded[14] = record.mode;
  encoded[15] = record.zone;
  encoded[16] = record.group1;
  encoded[17] = record.group2;
  encoded[18] = record.year;
  encoded[19] = record.month;
  encoded[20] = record.day;
  encoded[21] = record.level;
  encoded[22] = record.option;
  encoded.set(normalizeBytes(record.reserved, 3), 23);
  return encoded;
}

export function decodeUserRecord24(encoded: Uint8Array): UserRecord {
  if (encoded.length !== userRecordLength24) {
    throw new Error(`cannot decode SOYAL 87H user record: got ${encoded.length} bytes, want exactly ${userRecordLength24}`);
  }
  return {
    userAddress: 0,
    tagUid: encoded.slice(0, 8),
    pinCode: readUint32(encoded, 8),
    mode: encoded[12],
    zone: encoded[13],
    group1: encoded[14],
    group2: encoded[15],
    year: encoded[16],
    month: encoded[17],
    day: encoded[18],
    level: encoded[19],
    option: encoded[20],
    reserved: encoded.slice(21, 24),
  };
}

export function decodeUserAliases(encoded: Uint8Array, count = encoded.length / userAliasLength): string[] {
  if (!Number.isInteger(count) || count <= 0 || encoded.length !== count * userAliasLength) {
    throw new Error(`cannot decode SOYAL 2EH user aliases: got ${encoded.length} bytes for ${count} records`);
  }
  // SOYAL's Taiwan software stores the fixed-width alias field as Big5, not
  // UTF-8. Empty controller fields are commonly padded with FF bytes.
  const decoder = new TextDecoder("big5");
  return Array.from({ length: count }, (_, index) => {
    const field = encoded.slice(index * userAliasLength, (index + 1) * userAliasLength);
    let end = field.length;
    while (end > 0 && (field[end - 1] === 0 || field[end - 1] === 0xff || field[end - 1] === 0x20)) end -= 1;
    return end === 0 ? "" : decoder.decode(field.slice(0, end)).replace(/[\0 ]+$/g, "");
  });
}

export function buildMode(flags: ModeFlags): number {
  let mode = (flags.accessMode & 0x03) << 6;
  if (flags.patrol) mode |= 1 << 5;
  if (flags.cardOmittedAfterFingerprint) mode |= 1 << 4;
  if (flags.fingerprintOmittedAfterCard) mode |= 1 << 3;
  if (flags.enableExpireCheck) mode |= 1 << 2;
  if (flags.guest) mode |= 1 << 1;
  if (flags.passwordChangeAllowed) mode |= 1;
  return mode;
}

export function parseMode(mode: number): ModeFlags {
  return {
    accessMode: ((mode >> 6) & 0x03) as AccessMode,
    patrol: (mode & (1 << 5)) !== 0,
    cardOmittedAfterFingerprint: (mode & (1 << 4)) !== 0,
    fingerprintOmittedAfterCard: (mode & (1 << 3)) !== 0,
    enableExpireCheck: (mode & (1 << 2)) !== 0,
    guest: (mode & (1 << 1)) !== 0,
    passwordChangeAllowed: (mode & 1) !== 0,
  };
}

export function buildGuestAccessMode(flags: GuestAccessModeFlags): number {
  let mode = (flags.accessMode & 0x03) << 6;
  if (flags.patrol) mode |= 1 << 5;
  if (flags.cardOmittedAfterFingerprint) mode |= 1 << 4;
  if (flags.fingerprintOmittedAfterCard) mode |= 1 << 3;
  if (flags.enableExpireCheck) mode |= 1 << 2;
  if (flags.checkBeginAndEndTime) mode |= 1 << 1;
  if (flags.passwordChangeAllowed) mode |= 1;
  return mode;
}

export function parseGuestAccessMode(mode: number): GuestAccessModeFlags {
  return {
    accessMode: ((mode >> 6) & 0x03) as AccessMode,
    patrol: (mode & (1 << 5)) !== 0,
    cardOmittedAfterFingerprint: (mode & (1 << 4)) !== 0,
    fingerprintOmittedAfterCard: (mode & (1 << 3)) !== 0,
    enableExpireCheck: (mode & (1 << 2)) !== 0,
    checkBeginAndEndTime: (mode & (1 << 1)) !== 0,
    passwordChangeAllowed: (mode & 1) !== 0,
  };
}

export function buildSetGuestAccessBody(record: GuestAccessRecord): Uint8Array {
  validateGuestAccessAddress(record.userAddress);
  if ((record.mode & 1) !== 0) {
    throw new Error("cannot encode SOYAL 8BH guest record: Mode bit 0 must be zero");
  }
  if ((record.zone & 0x40) !== 0) {
    throw new Error("cannot encode SOYAL 8BH guest record: Zone reserved bit 6 must be zero");
  }
  const body = new Uint8Array(guestAccessBodyLength);
  body[0] = 0x8b;
  body[1] = 0x57;
  putGuestAccessAddress(body, 2, record.userAddress);
  body.set(normalizeBytes(record.tagUid, 8), 5);
  writeUint32(body, 13, record.pinCode);
  body[17] = record.mode;
  body[18] = record.zone;
  body[19] = record.group1;
  body[20] = record.group2;
  body[21] = record.beginYear;
  body[22] = record.beginMonth;
  body[23] = record.beginDay;
  body[24] = record.beginHour;
  body[25] = record.beginMinute;
  body[26] = record.endYear;
  body[27] = record.endMonth;
  body[28] = record.endDay;
  body[29] = record.endHour;
  body[30] = record.endMinute;
  body.set(normalizeBytes(record.lift, 4), 31);
  return body;
}

export function buildReadGuestAccessBody(userAddress: number): Uint8Array {
  validateGuestAccessAddress(userAddress);
  const body = new Uint8Array([0x8b, 0x52, 0, 0, 0]);
  putGuestAccessAddress(body, 2, userAddress);
  return body;
}

// 8BH read echoes can contain either the complete bare body or the frame
// payload, because parseFrame stores the function code separately.
export function decodeGuestAccessRecord(data: Uint8Array): GuestAccessRecord {
  let subCommandIndex: number;
  if (data.length === guestAccessBodyLength) {
    if (data[0] !== 0x8b) {
      throw new Error(`cannot decode SOYAL 8BH guest record: got command 0x${formatByte(data[0])}, want 0x8B`);
    }
    subCommandIndex = 1;
  } else if (data.length === guestAccessPayloadLength) {
    subCommandIndex = 0;
  } else if (data.length === guestAccessRecordLength) {
    // Some E-series controllers omit the 8BH read sub-command and return
    // only the three-byte address followed by the 30-byte record.
    subCommandIndex = -1;
  } else {
    throw new Error(`cannot decode SOYAL 8BH guest record: got ${data.length} bytes, want ${guestAccessBodyLength}-byte body, ${guestAccessPayloadLength}-byte frame payload, or ${guestAccessRecordLength}-byte record`);
  }
  if (subCommandIndex >= 0 && data[subCommandIndex] !== 0x52) {
    throw new Error(`cannot decode SOYAL 8BH guest record: got sub command 0x${formatByte(data[subCommandIndex])}, want 0x52`);
  }
  const addressIndex = subCommandIndex >= 0 ? subCommandIndex + 1 : 0;
  return {
    userAddress: (data[addressIndex] << 16) | (data[addressIndex + 1] << 8) | data[addressIndex + 2],
    tagUid: data.slice(addressIndex + 3, addressIndex + 11),
    pinCode: readUint32(data, addressIndex + 11),
    mode: data[addressIndex + 15],
    zone: data[addressIndex + 16],
    group1: data[addressIndex + 17],
    group2: data[addressIndex + 18],
    beginYear: data[addressIndex + 19],
    beginMonth: data[addressIndex + 20],
    beginDay: data[addressIndex + 21],
    beginHour: data[addressIndex + 22],
    beginMinute: data[addressIndex + 23],
    endYear: data[addressIndex + 24],
    endMonth: data[addressIndex + 25],
    endDay: data[addressIndex + 26],
    endHour: data[addressIndex + 27],
    endMinute: data[addressIndex + 28],
    lift: data.slice(addressIndex + 29, addressIndex + 33),
  };
}

export function setDoorBitmap(group1: number, group2: number, doorNumber: number, enabled: boolean): DoorBitmap {
  validateDoorNumber(doorNumber);
  if (doorNumber <= 8) {
    const mask = 1 << (doorNumber - 1);
    return { group1, group2: enabled ? group2 | mask : group2 & ~mask };
  }
  const mask = 1 << (doorNumber - 9);
  return { group1: enabled ? group1 | mask : group1 & ~mask, group2 };
}

export function readDoorBitmap(group1: number, group2: number, doorNumber: number): boolean {
  validateDoorNumber(doorNumber);
  return doorNumber <= 8
    ? (group2 & (1 << (doorNumber - 1))) !== 0
    : (group1 & (1 << (doorNumber - 9))) !== 0;
}

export function setDoorAccess(record: UserRecord, doorNumber: number, enabled: boolean): UserRecord {
  const bitmap = setDoorBitmap(record.group1, record.group2, doorNumber, enabled);
  return { ...record, group1: bitmap.group1, group2: bitmap.group2 };
}

export function hasDoorAccess(record: UserRecord, doorNumber: number): boolean {
  return readDoorBitmap(record.group1, record.group2, doorNumber);
}

export function doorsFromBitmap(group1: number, group2: number): number[] {
  const doors: number[] = [];
  for (let doorNumber = 1; doorNumber <= 16; doorNumber += 1) {
    if (readDoorBitmap(group1, group2, doorNumber)) doors.push(doorNumber);
  }
  return doors;
}

export function normalizeUid(value: string): string {
  const compact = value.trim().replace(/^0x/i, "").replace(/[\s:.-]/g, "");
  if (compact.length === 0 || compact.length > 16 || !/^[0-9a-f]+$/i.test(compact)) {
    throw new Error("card UID must contain 1 to 16 hexadecimal digits");
  }
  return compact.padStart(16, "0").toUpperCase();
}

export function uidBytes(value: string): Uint8Array {
  const normalized = normalizeUid(value);
  const bytes = new Uint8Array(8);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function uidString(value: Uint8Array): string | undefined {
  // A slot the controller has never held a card in reads back as all zeroes.
  // A slot 701Client or an 85H erase has cleared reads back as all 0xFF, with
  // the level, zone and expiry bytes set to 0xFF as well. Both mean "no card".
  // Treating 0xFF as a UID would report every unused address in a 16384-address
  // scan as an occupied slot, which would make the inventory and the
  // slot-collision gate built on it worthless.
  if (value.every((byte) => byte === 0)) return undefined;
  if (value.length > 0 && value.every((byte) => byte === 0xff)) return undefined;
  return Array.from(normalizeBytes(value, 8), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function validateGuestAccessAddress(address: number): void {
  if (!Number.isInteger(address) || address < 0 || address > 0xffffff) {
    throw new Error(`cannot use SOYAL 8BH user address ${address}: address must fit in 24 bits`);
  }
}

function validateDoorNumber(doorNumber: number): void {
  if (!Number.isInteger(doorNumber) || doorNumber < 1 || doorNumber > 16) {
    throw new Error(`invalid SOYAL door number ${doorNumber}: want a value from 1 through 16`);
  }
}

function putGuestAccessAddress(destination: Uint8Array, offset: number, address: number): void {
  destination[offset] = address >> 16;
  destination[offset + 1] = address >> 8;
  destination[offset + 2] = address;
}

function normalizeBytes(value: Uint8Array, length: number): Uint8Array {
  if (value.length !== length) {
    throw new Error(`SOYAL record field must contain exactly ${length} bytes, got ${value.length}`);
  }
  return value;
}

function writeUint32(destination: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`SOYAL 32-bit field is out of range: ${value}`);
  }
  destination[offset] = Math.floor(value / 0x1000000);
  destination[offset + 1] = (value >>> 16) & 0xff;
  destination[offset + 2] = (value >>> 8) & 0xff;
  destination[offset + 3] = value & 0xff;
}

function readUint32(source: Uint8Array, offset: number): number {
  return source[offset] * 0x1000000 + (source[offset + 1] << 16) + (source[offset + 2] << 8) + source[offset + 3];
}

function formatByte(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

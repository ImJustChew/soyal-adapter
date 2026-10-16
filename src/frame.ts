export const standardFrameHead = 0x7e;
export const securityFrameHead = 0x7f;
export const standardFrameDataLimit = 240;
export const maximumExtendedBodyLength = 0x0fff;

const standardExtendedPrefix = [0xff, 0x00, 0x5a, 0xa5];
const securityExtendedPrefix = [0xff, 0x00, 0x55, 0xaa];

export interface Frame {
  did: number;
  command: number;
  data: Uint8Array;
}

export function buildFrame(did: number, command: number, data: Uint8Array): Uint8Array {
  if (data.length > standardFrameDataLimit) {
    throw new Error(`cannot build SOYAL short frame: data length ${data.length} exceeds the ${standardFrameDataLimit}-byte limit`);
  }
  const body = buildFrameBody(did, command, data);
  const frame = new Uint8Array(2 + body.length);
  frame[0] = standardFrameHead;
  frame[1] = body.length;
  frame.set(body, 2);
  return frame;
}

// The extended frame stores the area in the high nibble of its two-byte body
// length field. It is used when the standard one-byte length is insufficient.
export function buildFrameExtended(area: number, did: number, command: number, data: Uint8Array): Uint8Array {
  if (!Number.isInteger(area) || area < 0 || area > 0x0f) {
    throw new Error(`cannot build SOYAL extended frame: area code 0x${area.toString(16).toUpperCase()} exceeds the four-bit limit`);
  }
  if (data.length > maximumExtendedBodyLength - 4) {
    throw new Error(`cannot build SOYAL extended frame: data length ${data.length} exceeds the ${maximumExtendedBodyLength - 4}-byte limit`);
  }
  const body = buildFrameBody(did, command, data);
  const frame = new Uint8Array(6 + body.length);
  frame.set(standardExtendedPrefix, 0);
  const declaredLength = (area << 12) | body.length;
  frame[4] = declaredLength >> 8;
  frame[5] = declaredLength & 0xff;
  frame.set(body, 6);
  return frame;
}

export function parseFrame(raw: Uint8Array): Frame {
  if (raw.length > 0 && raw[0] === securityFrameHead) {
    throw new Error("security mode frames are not supported");
  }
  if (hasPrefix(raw, securityExtendedPrefix)) {
    throw new Error("security mode frames are not supported");
  }
  if (hasPrefix(raw, standardExtendedPrefix)) {
    return parseExtendedFrame(raw);
  }
  return parseShortFrame(raw);
}

function parseShortFrame(raw: Uint8Array): Frame {
  if (raw.length === 0) {
    throw new Error("invalid SOYAL short frame header: frame is empty");
  }
  if (raw[0] !== standardFrameHead) {
    throw new Error(`invalid SOYAL short frame header: got 0x${formatByte(raw[0])}, want 0x${formatByte(standardFrameHead)}`);
  }
  if (raw.length < 2) {
    throw new Error("invalid SOYAL short frame length: missing declared length byte");
  }
  const declaredLength = raw[1];
  const actualLength = raw.length - 2;
  if (declaredLength !== actualLength) {
    throw new Error(`invalid SOYAL short frame length: declared ${declaredLength} bytes from DID through SUM, got ${actualLength}`);
  }
  if (declaredLength - 4 > standardFrameDataLimit) {
    throw new Error(`invalid SOYAL short frame data length: declared ${declaredLength - 4} data bytes exceeds the ${standardFrameDataLimit}-byte limit`);
  }
  return parseFrameBody(raw.subarray(2), "SOYAL short frame");
}

function parseExtendedFrame(raw: Uint8Array): Frame {
  if (raw.length < 6) {
    throw new Error("invalid SOYAL extended frame length: missing two-byte length field");
  }
  const declaredField = (raw[4] << 8) | raw[5];
  const declaredLength = declaredField & maximumExtendedBodyLength;
  const actualLength = raw.length - 6;
  if (declaredLength !== actualLength) {
    throw new Error(`invalid SOYAL extended frame length: declared ${declaredLength} bytes from DID through SUM, got ${actualLength}`);
  }
  return parseFrameBody(raw.subarray(6), "SOYAL extended frame");
}

function parseFrameBody(body: Uint8Array, frameDescription: string): Frame {
  if (body.length < 4) {
    throw new Error(`invalid ${frameDescription} length: body has ${body.length} bytes, need at least DID, command, XOR, and SUM`);
  }
  const expectedXor = calculateFrameXor(body.subarray(0, body.length - 2));
  const actualXor = body[body.length - 2];
  if (actualXor !== expectedXor) {
    throw new Error(`invalid ${frameDescription} XOR: got 0x${formatByte(actualXor)}, want 0x${formatByte(expectedXor)}`);
  }
  const expectedSum = calculateFrameSum(body.subarray(0, body.length - 2), expectedXor);
  const actualSum = body[body.length - 1];
  if (actualSum !== expectedSum) {
    throw new Error(`invalid ${frameDescription} SUM: got 0x${formatByte(actualSum)}, want 0x${formatByte(expectedSum)}`);
  }
  return {
    did: body[0],
    command: body[1],
    data: body.slice(2, body.length - 2),
  };
}

function buildFrameBody(did: number, command: number, data: Uint8Array): Uint8Array {
  const body = new Uint8Array(4 + data.length);
  body[0] = did;
  body[1] = command;
  body.set(data, 2);
  body[body.length - 2] = calculateFrameXor(body.subarray(0, body.length - 2));
  body[body.length - 1] = calculateFrameSum(body.subarray(0, body.length - 2), body[body.length - 2]);
  return body;
}

export function calculateFrameXor(values: Uint8Array): number {
  let checksum = 0xff;
  for (const value of values) checksum ^= value;
  return checksum;
}

export function calculateFrameSum(values: Uint8Array, xor: number): number {
  let sum = 0;
  for (const value of values) sum = (sum + value) & 0xff;
  return (sum + xor) & 0xff;
}

function hasPrefix(value: Uint8Array, prefix: number[]): boolean {
  if (value.length < prefix.length) return false;
  return prefix.every((expected, index) => value[index] === expected);
}

function formatByte(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

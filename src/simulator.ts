import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import {
  buildFrame,
  buildFrameExtended,
  parseFrame,
  standardFrameDataLimit,
  type Frame,
} from "./frame";
import {
  buildSetGuestAccessBody,
  decodeGuestAccessRecord,
  decodeUserRecord24,
  encodeUserRecord,
  type GuestAccessRecord,
} from "./record";
import type { EventRecord } from "./event";

const defaultSimulatorHost = "127.0.0.1";
const defaultSimulatorPort = 5510;
const defaultSimulatorNode = 2;
const defaultSimulatorArea = 0;
const defaultSimulatorCapacityMode = 16384;
const defaultSimulatorLogCapacity = 32000;
const defaultSimulatorSerial = "SIM7010001";
const defaultSimulatorIpMac = "127.0.0.1/00:13:57:70:10:01";
const defaultSimulatorFirmware = "4.04";
const defaultSimulatorModelCode = "0xC2";
const maximumSimulatorPointer = 0x1000000;
const maximumNode = 254;
const echoData = 0x03;
const echoAck = 0x04;
const echoNack = 0x05;
const standardExtendedPrefix = [0xff, 0x00, 0x5a, 0xa5] as const;

type DurationValue = number | string;

/** Configuration for one controller. A simulator instance owns one TCP port. */
export interface SimulatorConfig {
  host?: string;
  port?: number;
  node?: number;
  area?: number;
  capacityMode?: number;
  logCapacity?: number;
  doors?: number;
  doorCount?: number;
  clockDriftMs?: number;
  clockDrift?: DurationValue;
  /** Retained for callers that used the JSON simulator; the instance's node is the only address. */
  offlineNodes?: number[];
  rejectWrites?: boolean;
  nackRate?: number;
  dropRate?: number;
  /** Drop every reply, useful for exercising a transport timeout. */
  dropReplies?: boolean;
  dropReply?: boolean;
  latencyMs?: number;
  latency?: DurationValue;
  /** Alias for latencyMs that makes timeout tests self-documenting. */
  replyDelayMs?: number;
  delayReplyMs?: number;
  seed?: number;
  eventIntervalMs?: number;
  eventInterval?: DurationValue;
  serial?: string;
  ipMac?: string;
  firmware?: string;
  modelCode?: string;

  /** Reply command used when a write is refused. Usually 05H; 03H tests echo rejection. */
  writeEchoCode?: number;
  refuseWriteWith?: number;
  /** Fault injections apply after a valid response has been built. */
  splitReply?: boolean;
  splitReplies?: boolean;
  closeMidFrame?: boolean;
  closeMidFrameRate?: number;
  statusTrailingBytes?: number[];
}

export interface ResolvedSimulatorConfig {
  host: string;
  port: number;
  node: number;
  area: number;
  capacityMode: 16384 | 32768 | 65535;
  logCapacity: number;
  doors: number;
  clockDriftMs: number;
  offlineNodes: number[];
  rejectWrites: boolean;
  nackRate: number;
  dropRate: number;
  dropReplies: boolean;
  latencyMs: number;
  seed: number;
  eventIntervalMs: number;
  serial: string;
  ipMac: string;
  firmware: string;
  modelCode: string;
  writeEchoCode: number;
  splitReply: boolean;
  closeMidFrame: boolean;
  closeMidFrameRate: number;
  statusTrailingBytes: number[];
}

export type SimulatorEventInput = Partial<EventRecord> & {
  tagUid?: Uint8Array | string;
};

interface StoredSimulatorEvent {
  functionCode: number;
  data: Uint8Array;
}

interface IncomingFrame {
  frame: Frame;
  extended: boolean;
  area: number;
}

interface ReplyPlan {
  frame: Uint8Array;
  isEvent: boolean;
}

interface SimulatorSocketState {
  parser: BinaryFrameParser;
  queue: Promise<void>;
}

class SeededRandom {
  private state: number;

  public constructor(seed: number) {
    const normalizedSeed = Number.isSafeInteger(seed) ? seed : Date.now();
    this.state = (normalizedSeed >>> 0) || 0x6d2b79f5;
  }

  public next(): number {
    this.state = Math.imul(this.state ^ (this.state >>> 15), this.state | 1);
    this.state ^= this.state + Math.imul(this.state ^ (this.state >>> 7), this.state | 61);
    return ((this.state ^ (this.state >>> 14)) >>> 0) / 0x100000000;
  }
}

/**
 * Accumulates a TCP byte stream and extracts complete standard or extended
 * E-series frames. TCP segmentation is deliberately part of the simulator's
 * normal path: a frame is never assumed to equal one `data` callback.
 */
class BinaryFrameParser {
  private buffer: Uint8Array<ArrayBufferLike> = new Uint8Array();

  public push(chunk: Uint8Array): IncomingFrame[] {
    this.buffer = joinBytes(this.buffer, chunk);
    const frames: IncomingFrame[] = [];

    while (this.buffer.length > 0) {
      const start = this.findHeader();
      if (start < 0) {
        this.buffer = new Uint8Array();
        break;
      }
      if (start > 0) this.buffer = this.buffer.slice(start);

      const extended = this.buffer[0] === 0xff;
      if (extended) {
        if (this.buffer.length < 4) break;
        if (!hasPrefix(this.buffer, standardExtendedPrefix)) {
          this.buffer = this.buffer.slice(1);
          continue;
        }
        if (this.buffer.length < 6) break;
        const declaredLength = ((this.buffer[4] << 8) | this.buffer[5]) & 0x0fff;
        const totalLength = 6 + declaredLength;
        if (declaredLength < 4) {
          this.buffer = this.buffer.slice(1);
          continue;
        }
        if (this.buffer.length < totalLength) break;
        this.takeFrame(totalLength, true, frames);
        continue;
      }

      if (this.buffer[0] !== 0x7e) {
        this.buffer = this.buffer.slice(1);
        continue;
      }
      if (this.buffer.length < 2) break;
      const declaredLength = this.buffer[1];
      const totalLength = 2 + declaredLength;
      if (declaredLength < 4) {
        this.buffer = this.buffer.slice(1);
        continue;
      }
      if (this.buffer.length < totalLength) break;
      this.takeFrame(totalLength, false, frames);
    }

    return frames;
  }

  private takeFrame(totalLength: number, extended: boolean, frames: IncomingFrame[]): void {
    const raw = this.buffer.slice(0, totalLength);
    this.buffer = this.buffer.slice(totalLength);
    try {
      frames.push({
        frame: parseFrame(raw),
        extended,
        area: extended ? ((raw[4] >> 4) & 0x0f) : 0,
      });
    } catch {
      // A bad checksum, malformed length, or unsupported security frame is
      // ignored just as a controller ignores a damaged request.
    }
  }

  private findHeader(): number {
    for (let index = 0; index < this.buffer.length; index += 1) {
      if (this.buffer[index] === 0x7e || this.buffer[index] === 0xff) return index;
    }
    return -1;
  }
}

/** A stateful raw binary controller simulator. */
export class SoyalSimulator {
  public readonly config: ResolvedSimulatorConfig;

  private readonly users = new Map<number, Uint8Array>();
  private readonly guests = new Map<number, GuestAccessRecord>();
  private readonly aliases = new Map<number, string>();
  private readonly events = new Map<number, StoredSimulatorEvent>();
  private readonly sockets = new Set<Socket>();
  private readonly offlineNodes: ReadonlySet<number>;
  private readonly random: SeededRandom;
  private readonly doorRelays: boolean[];
  private clockOffsetMs: number;
  private server?: Server;
  private eventTimer?: ReturnType<typeof setInterval>;
  private servedSocket?: Socket;
  private readyPromise?: Promise<void>;
  private eventInputPointer = 0;
  private eventOutputPointer = 0;
  private eventLogCounter = 0;

  public constructor(config: SimulatorConfig = {}) {
    this.config = resolveSimulatorConfig(config);
    this.clockOffsetMs = this.config.clockDriftMs;
    this.offlineNodes = new Set(this.config.offlineNodes);
    this.random = new SeededRandom(this.config.seed);
    this.doorRelays = Array.from({ length: this.config.doors }, () => false);
  }

  public get host(): string {
    return this.config.host;
  }

  public get port(): number {
    const address = this.server?.address();
    return address !== null && typeof address === "object" ? address.port : this.config.port;
  }

  public get node(): number {
    return this.config.node;
  }

  public get inputPointer(): number {
    return this.eventInputPointer;
  }

  public get outputPointer(): number {
    return this.eventOutputPointer;
  }

  public get logCounter(): number {
    return this.eventLogCounter;
  }

  /** Start one raw TCP controller. The listener begins asynchronously. */
  public start(): this {
    if (this.server !== undefined) return this;
    this.server = createServer((socket) => this.acceptSocket(socket));
    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.server?.once("error", reject);
      this.server?.listen({ host: this.config.host, port: this.config.port }, () => resolve());
    });
    if (this.config.eventIntervalMs > 0) {
      this.eventTimer = setInterval(() => {
        this.appendEvent({ sourceNode: this.config.node, functionCode: 11, doorNumber: 1 });
      }, this.config.eventIntervalMs);
    }
    return this;
  }

  public async ready(): Promise<this> {
    this.start();
    await this.readyPromise;
    return this;
  }

  /** Stop the listener and synthetic event timer without touching controller state. */
  public stop(): void {
    if (this.eventTimer !== undefined) {
      clearInterval(this.eventTimer);
      this.eventTimer = undefined;
    }
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.servedSocket = undefined;
    const server = this.server;
    this.server = undefined;
    if (server !== undefined) {
      try {
        server.close();
      } catch {
        // A server that failed to bind is already closed.
      }
    }
  }

  public async close(): Promise<void> {
    this.stop();
  }

  /** Add an event without moving the consumer cursor. Returns its ring index. */
  public appendEvent(event: SimulatorEventInput = {}): number {
    const eventIndex = this.eventInputPointer;
    if (this.eventLogCounter === this.config.logCapacity) {
      this.events.delete(this.eventOutputPointer);
      this.eventOutputPointer = nextSimulatorPointer(this.eventOutputPointer);
    } else {
      this.eventLogCounter += 1;
    }
    const functionCode = event.functionCode ?? 11;
    const sourceNode = event.sourceNode ?? this.config.node;
    const eventData = encodeSimulatorEvent({ ...event, functionCode, sourceNode }, this.controllerTime());
    this.events.set(eventIndex, { functionCode, data: eventData });
    this.eventInputPointer = nextSimulatorPointer(this.eventInputPointer);
    return eventIndex;
  }

  public setUserAlias(address: number, alias: string): void {
    validateAddress(address, this.maxUserAddress(), "simulator alias address");
    if (typeof alias !== "string") throw new Error("simulator alias must be a string");
    this.aliases.set(address, alias);
  }

  public controllerTime(): Date {
    return new Date(Date.now() + this.clockOffsetMs);
  }

  private acceptSocket(socket: Socket): void {
    this.sockets.add(socket);
    socket.once("close", () => {
      this.sockets.delete(socket);
      if (this.servedSocket === socket) this.servedSocket = undefined;
    });
    socket.once("error", () => socket.destroy());
    if (this.servedSocket !== undefined) {
      // The hardware accepts the TCP connection, then closes the competing
      // client before it receives a complete response.
      socket.destroy();
      return;
    }
    this.servedSocket = socket;
    const state: SimulatorSocketState = { parser: new BinaryFrameParser(), queue: Promise.resolve() };
    socket.on("data", (chunk: Buffer) => {
      const frames = state.parser.push(chunk);
      for (const incoming of frames) {
        state.queue = state.queue
          .then(() => this.handleFrame(socket, incoming))
          .catch(() => { socket.destroy(); });
      }
    });
  }

  private async handleFrame(socket: Socket, incoming: IncomingFrame): Promise<void> {
    const request = incoming.frame;
    if (request.did !== this.config.node || !this.nodeOnline()) return;
    if (this.randomHit(this.config.dropRate) || this.config.dropReplies) return;

    let plan: ReplyPlan;
    try {
      plan = this.planReply(incoming);
    } catch {
      plan = { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    }
    if (this.config.latencyMs > 0) await waitMilliseconds(this.config.latencyMs);
    if (socket.destroyed) return;
    this.writeReply(socket, plan.frame);
  }

  private planReply(incoming: IncomingFrame): ReplyPlan {
    const { frame } = incoming;
    const body = new Uint8Array(1 + frame.data.length);
    body[0] = frame.command;
    body.set(frame.data, 1);

    switch (frame.command) {
      case 0x87:
        return { frame: this.buildReply(incoming, echoData, this.readUsers(body), true), isEvent: false };
      case 0x84:
        return this.planUserWrite(incoming, body);
      case 0x85:
        return this.planUserErase(incoming, body);
      case 0x8b:
        return this.planGuest(incoming, body);
      case 0x2e:
        return { frame: this.buildReply(incoming, echoData, this.readAliases(body), true), isEvent: false };
      case 0x24:
        return { frame: this.buildReply(incoming, echoData, this.clockData(), true), isEvent: false };
      case 0x23:
        return this.planClockWrite(incoming, body);
      case 0x25:
        return this.planEvent(incoming, body);
      case 0x12:
        return { frame: this.buildReply(incoming, echoData, this.parameterData(body[1] ?? 0), true), isEvent: false };
      case 0x18:
        return { frame: this.buildReply(incoming, echoData, this.statusData(), true), isEvent: false };
      default:
        return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    }
  }

  private planUserWrite(incoming: IncomingFrame, body: Uint8Array): ReplyPlan {
    if (body.length < 2) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const count = body[1];
    if (count === 0 || body.length < 2 + count * 26) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const records: Array<{ address: number; encoded: Uint8Array }> = [];
    try {
      for (let index = 0; index < count; index += 1) {
        const record = body.slice(2 + index * 26, 2 + (index + 1) * 26);
        const address = readUint16(record, 0);
        validateAddress(address, this.maxUserAddress(), "84H user address");
        decodeUserRecord24(record.slice(2));
        records.push({ address, encoded: record });
      }
    } catch {
      return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    }
    const responseCode = this.writeResponseCode();
    if (responseCode === echoAck) {
      for (const record of records) {
        this.users.set(record.address, record.encoded.slice());
        this.guests.delete(record.address);
      }
      return { frame: this.buildReply(incoming, echoAck, new Uint8Array()), isEvent: false };
    }
    return { frame: this.buildReply(incoming, responseCode, responseCode === echoData ? body.slice(1) : new Uint8Array()), isEvent: false };
  }

  private planUserErase(incoming: IncomingFrame, body: Uint8Array): ReplyPlan {
    if (body.length < 5) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const startAddress = readUint16(body, 1);
    const endAddress = readUint16(body, 3);
    if (endAddress < startAddress || endAddress - startAddress + 1 >= 1000 || endAddress > this.maxUserAddress()) {
      return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    }
    const responseCode = this.writeResponseCode();
    if (responseCode === echoAck) {
      for (let address = startAddress; address <= endAddress; address += 1) this.deleteUser(address);
    }
    return { frame: this.buildReply(incoming, responseCode, new Uint8Array()), isEvent: false };
  }

  private planGuest(incoming: IncomingFrame, body: Uint8Array): ReplyPlan {
    if (body.length < 5) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const subCommand = body[1];
    const address = readUint24(body, 2);
    if (address > this.maxUserAddress()) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    if (subCommand === 0x57) {
      if (body.length < 35) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
      let guest: GuestAccessRecord;
      try {
        const readable = body.slice(0, 35);
        readable[1] = 0x52;
        guest = decodeGuestAccessRecord(readable);
      } catch {
        return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
      }
      const responseCode = this.writeResponseCode();
      if (responseCode === echoAck) {
        this.guests.set(address, guest);
        this.users.set(address, encodeUserRecord({
          userAddress: address,
          tagUid: guest.tagUid,
          pinCode: guest.pinCode,
          mode: guest.mode,
          zone: guest.zone,
          group1: guest.group1,
          group2: guest.group2,
          year: guest.endYear,
          month: guest.endMonth,
          day: guest.endDay,
          level: 0,
          option: 0,
          reserved: new Uint8Array(3),
        }));
      }
      return { frame: this.buildReply(incoming, responseCode, responseCode === echoData ? body.slice(1) : new Uint8Array()), isEvent: false };
    }
    if (subCommand === 0x52) {
      const guest = this.guests.get(address) ?? emptyGuestAccessRecord(address);
      const readable = buildSetGuestAccessBody(guest);
      readable[1] = 0x52;
      return { frame: this.buildReply(incoming, echoData, readable.slice(1)), isEvent: false };
    }
    return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
  }

  private planClockWrite(incoming: IncomingFrame, body: Uint8Array): ReplyPlan {
    if (body.length < 8) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const responseCode = this.writeResponseCode();
    if (responseCode === echoAck) {
      const value = new Date(2000 + body[7], body[6] - 1, body[5], body[3], body[2], body[1]);
      if (Number.isNaN(value.getTime())) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
      this.setControllerTime(value);
    }
    return { frame: this.buildReply(incoming, responseCode, new Uint8Array()), isEvent: false };
  }

  private planEvent(incoming: IncomingFrame, body: Uint8Array): ReplyPlan {
    if (body.length === 1) {
      const event = this.events.get(this.eventOutputPointer);
      if (event === undefined) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
      // 25H indexed/oldest event replies use the event function code as the
      // command byte; the 29-byte record itself starts with source node.
      return { frame: this.buildReply(incoming, event.functionCode, event.data, true), isEvent: true };
    }
    if (body.length !== 4) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    const index = readUint24(body, 1);
    if (index === 0xffffff) return { frame: this.buildReply(incoming, echoData, this.eventStatusData(), true), isEvent: false };
    const event = this.events.get(index);
    if (event === undefined) return { frame: this.buildReply(incoming, echoNack, new Uint8Array()), isEvent: false };
    return { frame: this.buildReply(incoming, event.functionCode, event.data, true), isEvent: true };
  }

  private readUsers(body: Uint8Array): Uint8Array {
    if (body.length < 4) throw new Error("87H body is too short");
    const startAddress = readUint16(body, 1);
    const count = body[3];
    const maximumCount = Math.floor((standardFrameDataLimit - 1) / 24);
    if (count === 0 || count > maximumCount || startAddress + count - 1 > this.maxUserAddress()) throw new Error("87H request is outside the controller's readable frame window");
    const data = new Uint8Array(1 + count * 24);
    data[0] = this.config.node;
    for (let index = 0; index < count; index += 1) {
      const record = this.users.get(startAddress + index);
      if (record !== undefined) data.set(record.slice(2), 1 + index * 24);
    }
    return data;
  }

  private readAliases(body: Uint8Array): Uint8Array {
    if (body.length < 5) throw new Error("2EH body is too short");
    const start = readUint24(body, 1);
    const count = body[4];
    if (count === 0 || start + count - 1 > this.maxUserAddress()) throw new Error("2EH request is outside the controller's address range");
    const data = new Uint8Array(1 + count * 16).fill(0xff);
    data[0] = this.config.node;
    const encoder = new TextEncoder();
    for (let index = 0; index < count; index += 1) data.set(encoder.encode(this.aliases.get(start + index) ?? "").slice(0, 16), 1 + index * 16);
    return data;
  }

  private parameterData(subCode: number): Uint8Array {
    switch (subCode) {
      case 0x00: {
        const data = new Uint8Array(1 + 50);
        data[0] = this.config.node;
        data.set(new TextEncoder().encode(this.config.firmware).slice(0, 10), 41);
        const mode = capacityModeCode(this.config.capacityMode);
        data[49] = mode;
        data[50] = mode;
        return data;
      }
      case 0x14:
        return joinBytes(new Uint8Array([this.config.node]), this.ipMacBytes());
      case 0x15: {
        const available = Math.max(0, this.config.capacityMode - this.users.size);
        return new Uint8Array([this.config.node, 0, 0, available >> 8, available]);
      }
      case 0xfe: {
        const data = new Uint8Array(1 + 14);
        data[0] = this.config.node;
        data[2] = 0x02;
        data.set(new TextEncoder().encode(this.config.serial).slice(0, 12), 3);
        return data;
      }
      default:
        return new Uint8Array([this.config.node, 0]);
    }
  }

  private ipMacBytes(): Uint8Array {
    const bytes = new Uint8Array(31);
    const parts = this.config.ipMac.split(/[\/,;\s]+/).filter((part) => part.length > 0);
    if (parts.length === 2) {
      const ip = parseIpv4(parts[0]);
      const mac = parseMac(parts[1]);
      if (ip !== undefined && mac !== undefined) {
        bytes.set(mac, 1);
        bytes.set(ip, 7);
      }
    }
    bytes.set([255, 255, 255, 0], 11);
    bytes.set([192, 168, 0, 254], 15);
    bytes[19] = 1621 >> 8;
    bytes[20] = 1621 & 0xff;
    bytes[29] = 0;
    bytes[30] = 80;
    return bytes;
  }

  private clockData(): Uint8Array {
    const clock = this.controllerTime();
    return new Uint8Array([this.config.node, clock.getSeconds(), clock.getMinutes(), clock.getHours(), clock.getDay() + 1, clock.getDate(), clock.getMonth() + 1, clock.getFullYear() - 2000]);
  }

  private statusData(): Uint8Array {
    const clock = this.controllerTime();
    let flags = 0;
    if (this.doorRelays.some(Boolean)) flags |= 1 << 4;
    return new Uint8Array([this.config.node, clock.getSeconds(), clock.getMinutes(), clock.getHours(), clock.getDay() + 1, flags, 0]);
  }

  private eventStatusData(): Uint8Array {
    const data = new Uint8Array(1 + 9 + this.config.statusTrailingBytes.length);
    data[0] = this.config.node;
    putUint24(data, 1, this.eventLogCounter);
    putUint24(data, 4, this.eventInputPointer);
    putUint24(data, 7, this.eventOutputPointer);
    data.set(this.config.statusTrailingBytes, 10);
    return data;
  }

  private buildReply(incoming: IncomingFrame, command: number, payload: Uint8Array, payloadIncludesSource = false): Uint8Array {
    const data = payloadIncludesSource ? payload : joinBytes(new Uint8Array([this.config.node]), payload);
    const extended = incoming.extended || data.length > standardFrameDataLimit;
    return extended
      ? buildFrameExtended(incoming.area || this.config.area, 0, command, data)
      : buildFrame(0, command, data);
  }

  private writeReply(socket: Socket, frame: Uint8Array): void {
    const closeMidFrame = this.config.closeMidFrame || this.randomHit(this.config.closeMidFrameRate);
    if (closeMidFrame) {
      const splitAt = Math.max(1, Math.floor(frame.length / 2));
      socket.write(Buffer.from(frame.slice(0, splitAt)));
      socket.destroy();
      return;
    }
    if (this.config.splitReply) {
      const splitAt = Math.max(1, Math.floor(frame.length / 2));
      socket.write(Buffer.from(frame.slice(0, splitAt)));
      setTimeout(() => {
        if (!socket.destroyed) socket.write(Buffer.from(frame.slice(splitAt)));
      }, 1);
      return;
    }
    socket.write(Buffer.from(frame));
  }

  private writeResponseCode(): number {
    const refused = this.config.rejectWrites || this.randomHit(this.config.nackRate);
    return refused ? this.config.writeEchoCode : echoAck;
  }

  private setControllerTime(value: Date): void {
    this.clockOffsetMs = value.getTime() - Date.now();
  }

  private deleteUser(address: number): void {
    this.users.delete(address);
    this.guests.delete(address);
    this.aliases.delete(address);
  }

  private nodeOnline(): boolean {
    return !this.offlineNodes.has(this.config.node);
  }

  private maxUserAddress(): number {
    return Math.min(this.config.capacityMode - 1, 0xffff);
  }

  private randomHit(rate: number): boolean {
    return rate > 0 && this.random.next() < rate;
  }
}

export function createSoyalSimulator(config: SimulatorConfig = {}): SoyalSimulator {
  return new SoyalSimulator(config);
}

export function startSoyalSimulator(config: SimulatorConfig = {}): SoyalSimulator {
  return new SoyalSimulator(config).start();
}

function resolveSimulatorConfig(config: SimulatorConfig): ResolvedSimulatorConfig {
  const capacityMode = config.capacityMode ?? defaultSimulatorCapacityMode;
  if (capacityMode !== 16384 && capacityMode !== 32768 && capacityMode !== 65535) throw new Error("simulator capacity mode must be 16384, 32768, or 65535");
  const logCapacity = config.logCapacity ?? defaultSimulatorLogCapacity;
  if (!Number.isInteger(logCapacity) || logCapacity < 1 || logCapacity >= maximumSimulatorPointer) throw new Error(`simulator log capacity must be from 1 through ${maximumSimulatorPointer - 1}`);
  const host = config.host ?? defaultSimulatorHost;
  if (host.trim().length === 0) throw new Error("simulator host must not be empty");
  const port = config.port ?? defaultSimulatorPort;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("simulator port must be from 0 through 65535");
  const node = config.node ?? defaultSimulatorNode;
  validateNode(node, "simulator node");
  const area = config.area ?? defaultSimulatorArea;
  if (!Number.isInteger(area) || area < 0 || area > 15) throw new Error("simulator area must be from 0 through 15");
  const doors = config.doors ?? config.doorCount ?? 2;
  if (!Number.isInteger(doors) || doors < 1 || doors > 16) throw new Error("simulator doors must be from 1 through 16");
  const clockDriftMs = durationMilliseconds(config.clockDriftMs ?? config.clockDrift ?? 0, "clock-drift");
  const latencyMs = durationMilliseconds(config.replyDelayMs ?? config.delayReplyMs ?? config.latencyMs ?? config.latency ?? 0, "latency");
  const eventIntervalMs = durationMilliseconds(config.eventIntervalMs ?? config.eventInterval ?? 0, "event-interval");
  const nackRate = rateValue(config.nackRate ?? 0, "nack-rate");
  const dropRate = rateValue(config.dropRate ?? 0, "drop-rate");
  const closeMidFrameRate = rateValue(config.closeMidFrameRate ?? 0, "close-mid-frame-rate");
  const offlineNodes = [...(config.offlineNodes ?? [])];
  for (const offlineNode of offlineNodes) validateNode(offlineNode, "simulator offline node");
  const seed = config.seed ?? Date.now();
  if (!Number.isFinite(seed)) throw new Error("simulator seed must be finite");
  const writeEchoCode = config.writeEchoCode ?? config.refuseWriteWith ?? echoNack;
  if (!Number.isInteger(writeEchoCode) || writeEchoCode < 0 || writeEchoCode > 255) throw new Error("simulator write echo code must fit in one byte");
  const statusTrailingBytes = [...(config.statusTrailingBytes ?? [])];
  if (statusTrailingBytes.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) throw new Error("simulator status trailing bytes must be bytes");
  return {
    host,
    port,
    node,
    area,
    capacityMode,
    logCapacity,
    doors,
    clockDriftMs,
    offlineNodes,
    rejectWrites: config.rejectWrites ?? false,
    nackRate,
    dropRate,
    dropReplies: config.dropReplies ?? config.dropReply ?? false,
    latencyMs,
    seed,
    eventIntervalMs,
    serial: config.serial ?? defaultSimulatorSerial,
    ipMac: config.ipMac ?? defaultSimulatorIpMac,
    firmware: config.firmware ?? defaultSimulatorFirmware,
    modelCode: config.modelCode ?? defaultSimulatorModelCode,
    writeEchoCode,
    splitReply: config.splitReply ?? config.splitReplies ?? false,
    closeMidFrame: config.closeMidFrame ?? false,
    closeMidFrameRate,
    statusTrailingBytes,
  };
}

function durationMilliseconds(value: DurationValue, name: string): number {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative duration`);
    return value;
  }
  const text = value.trim();
  if (text === "0") return 0;
  const pattern = /([+-]?\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
  let totalMilliseconds = 0;
  let matched = "";
  for (const match of text.matchAll(pattern)) {
    matched += match[0];
    const amount = Number(match[1]);
    const unit = match[2];
    const factor = unit === "ns" ? 0.000001 : unit === "us" || unit === "µs" ? 0.001 : unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000;
    totalMilliseconds += amount * factor;
  }
  if (matched !== text || !Number.isFinite(totalMilliseconds) || totalMilliseconds < 0) throw new Error(`${name} must be a non-negative duration`);
  return totalMilliseconds;
}

function rateValue(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0 || value > 1) throw new Error(`${name} must be from 0 through 1`);
  return value;
}

function validateNode(node: number, name: string): void {
  if (!Number.isInteger(node) || node < 1 || node > maximumNode) throw new Error(`${name} ${node} must be from 1 through ${maximumNode}`);
}

function validateAddress(address: number, maximum: number, name: string): void {
  if (!Number.isInteger(address) || address < 0 || address > maximum) throw new Error(`${name} ${address} is outside the controller address range`);
}

function encodeSimulatorEvent(event: SimulatorEventInput, fallbackTime: Date): Uint8Array {
  const timestamp = event.month !== undefined && event.month !== 0 && event.day !== undefined && event.day !== 0
    ? new Date(2000 + (event.year ?? 0), (event.month ?? 1) - 1, event.day, event.hour ?? 0, event.minute ?? 0, event.second ?? 0)
    : fallbackTime;
  const data = new Uint8Array(29);
  const tagUid = typeof event.tagUid === "string" ? decodeHexUid(event.tagUid) : event.tagUid !== undefined && event.tagUid.length === 8 ? event.tagUid : new Uint8Array(8);
  data[0] = event.sourceNode ?? 1;
  data[1] = timestamp.getSeconds();
  data[2] = timestamp.getMinutes();
  data[3] = timestamp.getHours();
  data[4] = timestamp.getDay() + 1;
  data[5] = timestamp.getDate();
  data[6] = timestamp.getMonth() + 1;
  data[7] = timestamp.getFullYear() - 2000;
  data[8] = event.port ?? 0;
  data[9] = (event.userAddress ?? 0) >> 8;
  data[10] = event.userAddress ?? 0;
  data[11] = event.subCode ?? 0;
  data[12] = event.subFunction ?? 0;
  data[13] = event.extCode ?? 0;
  data[14] = (event.userLevel ?? 0) & 0x3f;
  if (event.freeAccess) data[14] |= 0x40;
  if (event.multiDoorOrWg) data[14] |= 0x80;
  data[15] = tagUid[4];
  data[16] = tagUid[5];
  data[17] = event.doorNumber ?? 0;
  data[19] = tagUid[6];
  data[20] = tagUid[7];
  data[21] = tagUid[2];
  data[22] = tagUid[3];
  data[23] = tagUid[0];
  data[24] = tagUid[1];
  return data;
}

function emptyGuestAccessRecord(address: number): GuestAccessRecord {
  return {
    userAddress: address,
    tagUid: new Uint8Array(8),
    pinCode: 0,
    mode: 0,
    zone: 0,
    group1: 0,
    group2: 0,
    beginYear: 0,
    beginMonth: 0,
    beginDay: 0,
    beginHour: 0,
    beginMinute: 0,
    endYear: 0,
    endMonth: 0,
    endDay: 0,
    endHour: 0,
    endMinute: 0,
    lift: new Uint8Array(4),
  };
}

function decodeHexUid(value: string): Uint8Array {
  const compact = value.trim().replace(/^0x/i, "").replace(/[\s:.-]/g, "");
  if (compact.length === 0 || compact.length > 16 || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) throw new Error("event UID must be an even hexadecimal value of at most eight bytes");
  const padded = compact.padStart(16, "0");
  return new Uint8Array(Array.from({ length: 8 }, (_, index) => Number.parseInt(padded.slice(index * 2, index * 2 + 2), 16)));
}

function joinBytes(first: Uint8Array, second: Uint8Array): Uint8Array {
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first);
  joined.set(second, first.length);
  return joined;
}

function putUint24(destination: Uint8Array, offset: number, value: number): void {
  destination[offset] = value >> 16;
  destination[offset + 1] = value >> 8;
  destination[offset + 2] = value;
}

function readUint16(source: Uint8Array, offset: number): number {
  return (source[offset] << 8) | source[offset + 1];
}

function readUint24(source: Uint8Array, offset: number): number {
  return (source[offset] << 16) | (source[offset + 1] << 8) | source[offset + 2];
}

function nextSimulatorPointer(value: number): number {
  return (value + 1) % maximumSimulatorPointer;
}

function capacityModeCode(capacityMode: number): number {
  if (capacityMode === 32768) return 1;
  if (capacityMode === 65535) return 2;
  return 0;
}

function parseIpv4(value: string): Uint8Array | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  const bytes = parts.map((part) => Number(part));
  if (bytes.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return new Uint8Array(bytes);
}

function parseMac(value: string): Uint8Array | undefined {
  const parts = value.split(/[:-]/);
  if (parts.length !== 6 || parts.some((part) => !/^[0-9a-f]{2}$/i.test(part))) return undefined;
  return new Uint8Array(parts.map((part) => Number.parseInt(part, 16)));
}

function hasPrefix(value: Uint8Array, prefix: readonly number[]): boolean {
  return value.length >= prefix.length && prefix.every((expected, index) => value[index] === expected);
}

function waitMilliseconds(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

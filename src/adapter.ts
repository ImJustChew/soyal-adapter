import { buildEraseUserRangeBody, buildEventLogQueueStatusBody, buildEventLogRecordBody, buildGetParameterBody, buildReadClockBody, buildReadUserAliasBody, buildReadUserBody, buildSetClockBody, buildSetUserBody } from "./command";
import { buildReadGuestAccessBody, buildSetGuestAccessBody, buildGuestAccessMode, buildMode, decodeGuestAccessRecord, decodeUserAliases, decodeUserRecord24, doorsFromBitmap, guestAccessRecordLength, userAliasLength, type GuestAccessRecord, type UserRecord, AccessMode, uidBytes, uidString } from "./record";
import type { Frame } from "./frame";
import { decodeEventQueueStatus, decodeEventRecord, eventQueueStatusDataLength, eventTime, type EventRecord } from "./event";
import { SoyalWireError, type SoyalWire } from "./wire";
import { controllerWallClockToDate } from "./timezone";

// This site's own pre-existing 84H cards all store 2079-12-31 as a de facto
// "never expires" date even with the expiry-check bit off. See the comment
// on writeUserCredential's record build for how that was confirmed.
const openEndedUserRecordYear = 79;

export enum CommandOutcome {
  OK = "ok",
  Rejected = "rejected",
  Failed = "failed",
  Unsupported = "unsupported",
}

export interface AdapterArguments {
  [key: string]: unknown;
}

export interface AdapterResult<T = unknown> {
  outcome: CommandOutcome;
  code?: string;
  detail?: string;
  data?: T;
}

export interface Controller {
  area: number;
  node: number;
}

export interface ControllerHealth extends Controller {
  online: boolean;
  lastSeenAt?: Date;
}

export interface Credential {
  address: number;
  tagUid: string | null;
  doors: number[];
  validFrom: Date | null;
  validUntil: Date | null;
  actualHash: string;
}

export interface CredentialPageBody {
  credentials: Credential[];
  cursor: string | null;
  done: boolean;
}

export interface UserAliasPageBody {
  aliases: Array<{ address: number; alias: string }>;
  cursor: string | null;
  done: boolean;
}

export interface EventPullBody {
  events: BridgeEvent[];
  controller: Controller;
  cursor: string;
}

export interface EventPointerAheadData {
  previousCursor: number;
  observedPointer: number;
}

export interface BridgeEvent {
  kind: "event" | "gap";
  controller: Controller;
  /** The node/area identity stored in the controller's 25H record. */
  deviceSourceNode?: number;
  door?: number;
  functionCode?: number;
  userAddress?: number;
  tagUid?: string;
  deviceTime?: Date;
  deviceTimezone?: string;
  bridgeReceivedAt?: Date;
  dedupeKey?: string;
  raw?: string;
  estimatedCount?: number;
  reason?: string;
}

export interface ClockReading {
  controllerTime: Date;
  bridgeTime: Date;
  clockDriftMs: number;
}

export interface CommissionResult {
  serial: string;
  ip: string;
  mac: string;
  /** Null means the controller returned a mode code this package cannot source. */
  capacityMode: number | null;
  capacityModeCode: number;
  availableUsers: number;
  controllerTime: Date;
  bridgeTime: Date;
  clockDriftMs: number;
}

export interface SoyalAdapterConfig {
  siteId?: string;
  area?: number;
  node?: number;
  nodeStart?: number;
  nodeEnd?: number;
  credentialWriteMode?: "8BH" | "84H" | string;
  controllerTimezone?: string;
  capabilities?: Iterable<string>;
}

export interface EventCursorStore {
  eventCursor(key: string): number | undefined;
}

const allCapabilities = [
  "writeCredential",
  "deleteCredential",
  "readCredential",
  "listCredentials",
  "listUserAliases",
  "pullEvents",
  "controlDoor",
  "commission",
  "syncClock",
  "readClock",
  "readClockBatch",
  "discover",
  "probe",
] as const;

const echoData = 0x03;
const echoAck = 0x04;
// A four-record 87H window is accepted by the measured controllers and keeps
// the requested address inside a single direct read.
const readUserWindowCount = 4;

// 12H sub 14H echo, protocol document section 2.2.13: data 00 through 30.
const networkParameterLength = 31;

// 12H sub FEH echo, protocol document section 2.2.20: two flash-size bytes
// followed by a twelve byte CPU serial number.
const controllerSerialLength = 12;
const serialParameterLength = 2 + controllerSerialLength;
const maximumArea = 15;
const maximumNode = 254;

// A 256-record page bounds one pull to about 7 seconds at the measured
// 28-ms-per-record direct-read rate, leaving room for queue-status and
// persistence work without turning a several-thousand-record backlog into a
// single uninterruptible pull.
export const EVENT_PULL_PAGE_SIZE = 256;
const eventRingCapacity = 32_000;

export interface ResolvedSoyalAdapterConfig {
  siteId: string;
  area: number;
  node: number;
  nodeStart: number;
  nodeEnd: number;
  credentialWriteMode: "8BH" | "84H";
  controllerTimezone: string;
}

export class SoyalAdapter {
  public readonly config: ResolvedSoyalAdapterConfig;
  public readonly capabilities: Set<string>;
  public pageSize = 64;

  private readonly wire: SoyalWire;
  private readonly eventCursors = new Map<string, number>();
  private eventCursorStore?: EventCursorStore;

  public constructor(config: SoyalAdapterConfig, wire: SoyalWire) {
    const credentialWriteMode = (config.credentialWriteMode ?? "84H").trim().toUpperCase();
    if (credentialWriteMode !== "8BH" && credentialWriteMode !== "84H") {
      throw new Error("SOYAL credential write mode must be 8BH or 84H");
    }
    const area = config.area ?? 0;
    if (!Number.isInteger(area) || area < 0 || area > maximumArea) {
      throw new Error(`SOYAL Area must be an integer from 0 through ${maximumArea}`);
    }
    const node = config.node ?? 1;
    const nodeStart = config.nodeStart ?? node;
    const nodeEnd = config.nodeEnd ?? node;
    validateNode(node, "node");
    validateNode(nodeStart, "nodeStart");
    validateNode(nodeEnd, "nodeEnd");
    if (nodeEnd < nodeStart) throw new Error("SOYAL nodeEnd must not be less than nodeStart");
    this.config = {
      siteId: config.siteId ?? "",
      area,
      node,
      nodeStart,
      nodeEnd,
      credentialWriteMode,
      controllerTimezone: config.controllerTimezone ?? "",
    };
    this.capabilities = new Set(config.capabilities ?? allCapabilities);
    this.wire = wire;
  }

  public setEventCursorStore(store: EventCursorStore): void {
    this.eventCursorStore = store;
  }

  public caps(): string[] {
    return allCapabilities.filter((capability) => this.capabilities.has(capability));
  }

  public async writeCredential(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult> {
    const unsupported = this.unsupported("writeCredential");
    if (unsupported) return unsupported;
    return this.executeWriteWithRetry(async () => {
      try {
        const address = this.address(args, "address", 16383);
        const desired = desiredArguments(args);
        const tagUid = uidBytes(stringArgument(desired, "tagUid", "tagUID"));
        const bitmap = doorNumbers(desired);
        const accessMode = desiredAccessMode(desired);
        // Bytes 64-127 have Zone bit 6 set, which encodeUserRecord/
        // buildSetGuestAccessBody both reject -- only 0-63 and 128-191 are
        // real controller-configured table entries.
        const zone = integerArgument(desired, "zone", 0, 0, 191);
        const configuredMode = typeof desired.mode === "string" && desired.mode.trim().toUpperCase() === "84H"
          ? "84H"
          : this.config.credentialWriteMode;
        const controller = this.controller(args);
        if (configuredMode === "84H") {
          return await this.writeUserCredential(controller, desired, address, tagUid, bitmap, accessMode, zone, signal);
        }
        return await this.writeGuestCredential(controller, desired, address, tagUid, bitmap, accessMode, zone, signal);
      } catch (error) {
        return this.operationError(error);
      }
    }, signal);
  }

  public async deleteCredential(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult> {
    const unsupported = this.unsupported("deleteCredential");
    if (unsupported) return unsupported;
    return this.executeWriteWithRetry(async () => {
      try {
        const address = this.address(args, "address", 16383);
        const controller = this.controller(args);
        const response = await this.execute(controller, buildEraseUserRangeBody(address, address), signal);
        const confirmation = this.confirmWriteAck(response);
        if (confirmation.outcome !== CommandOutcome.OK) return confirmation;
        return okResult();
      } catch (error) {
        return this.operationError(error);
      }
    }, signal);
  }

  // Keep the write operation boundary so callers can run the write and their
  // device read-back under wire.withExclusive. Transport retries belong to the
  // direct wire; a door/credential write must not be replayed by this layer.
  private async executeWriteWithRetry(operation: () => Promise<AdapterResult>, signal?: AbortSignal): Promise<AdapterResult> {
    void signal;
    return operation();
  }

  public async readCredential(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult<Credential>> {
    const unsupported = this.unsupported("readCredential");
    if (unsupported) return unsupported as AdapterResult<Credential>;
    try {
      const address = this.address(args, "address", 16383);
      const readMode = typeof args.mode === "string" && args.mode.trim().toUpperCase() === "84H"
        ? "84H"
        : this.config.credentialWriteMode;
      const requestConfig = { ...this.config, ...this.controller(args) };
      if (readMode === "84H") {
        // Read a four-record window containing the address rather than a
        // single record. Measured over 60 trials, counts of 2, 4, 5, 6 and 8
        // all succeed on both nodes; a count of 1 failed on the first two
        // attempts made against each node and later succeeded only after
        // retries. Nine records is the documented ceiling, so four sits well
        // inside it and reads no slower than one.
        const windowCount = readUserWindowCount;
        const windowStart = Math.min(address, 16384 - windowCount);
        const windowOffset = address - windowStart;
        const response = await this.execute(requestConfig, buildReadUserBody(windowStart, windowCount), signal);
        const decoded = this.decodeDataEcho(response);
        if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<Credential>;
        const data = controllerPayload(decoded.frame.data, requestConfig.node, 24 * windowCount, "87H response");
        const record = decodeUserRecord24(data.slice(windowOffset * 24, windowOffset * 24 + 24));
        record.userAddress = address;
        return okResult(await credentialFromUser(record, frameBytes(decoded.frame)));
      }
      const response = await this.execute(requestConfig, buildReadGuestAccessBody(address), signal);
      const decoded = this.decodeDataEcho(response);
      if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<Credential>;
      const data = controllerPayload(decoded.frame.data, requestConfig.node, [guestAccessRecordLength, 34, 35], "8BH response");
      const record = decodeGuestAccessRecord(data);
      record.userAddress = address;
      return okResult(await credentialFromGuest(record, frameBytes(decoded.frame)));
    } catch (error) {
      return this.operationError(error) as AdapterResult<Credential>;
    }
  }

  public async listCredentials(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult<CredentialPageBody>> {
    const unsupported = this.unsupported("listCredentials");
    if (unsupported) return unsupported as AdapterResult<CredentialPageBody>;
    try {
      const range = this.credentialRange(args);
      let cursor = cursorAddress(args, range.start);
      if (cursor > range.end) return okResult({ credentials: [], cursor: null, done: true });
      let count = this.pageSize;
      if (!Number.isInteger(count) || count <= 0 || count > 255) count = 64;
      count = Math.min(count, range.end - cursor + 1);
      const requestConfig = { ...this.config, area: range.controller.area, node: range.controller.node };

      // Read back the same record family used by writes. Guest records have no
      // bulk read, so each guest page is one request per address; 87H users can
      // be read in a single request of up to 64 records.
      if (this.config.credentialWriteMode !== "84H") {
        count = Math.min(count, 16);
        const credentials: Credential[] = [];
        for (let offset = 0; offset < count; offset += 1) {
          const address = cursor + offset;
          const response = await this.execute(requestConfig, buildReadGuestAccessBody(address), signal);
          const decoded = this.decodeDataEcho(response);
          if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<CredentialPageBody>;
          const data = controllerPayload(decoded.frame.data, requestConfig.node, [guestAccessRecordLength, 34, 35], "8BH response");
          const record = decodeGuestAccessRecord(data);
          record.userAddress = address;
          credentials.push(await credentialFromGuest(record, decoded.frame.data));
        }
        cursor += count;
        return okResult(pageBody(credentials, cursor, range.end));
      }

      let response: Frame;
      try {
        response = await this.execute(requestConfig, buildReadUserBody(cursor, count), signal);
      } catch (error) {
        if (count === 1) throw error;
        return this.readUserCredentialsIndividually(requestConfig, cursor, count, range.end, signal);
      }
      const decoded = this.decodeDataEcho(response);
      if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<CredentialPageBody>;
      let data: Uint8Array;
      try {
        data = controllerPayload(decoded.frame.data, requestConfig.node, count * 24, `87H page for ${count} records`);
      } catch (error) {
        if (count === 1) throw error;
        return this.readUserCredentialsIndividually(requestConfig, cursor, count, range.end, signal);
      }
      const credentials: Credential[] = [];
      for (let index = 0; index < count; index += 1) {
        const record = decodeUserRecord24(data.slice(index * 24, (index + 1) * 24));
        record.userAddress = cursor + index;
        credentials.push(await credentialFromUser(record, data.slice(index * 24, (index + 1) * 24)));
      }
      cursor += count;
      return okResult(pageBody(credentials, cursor, range.end));
    } catch (error) {
      return this.operationError(error) as AdapterResult<CredentialPageBody>;
    }
  }

  private async readUserCredentialsIndividually(
    requestConfig: ResolvedSoyalAdapterConfig,
    cursor: number,
    count: number,
    rangeEnd: number,
    signal?: AbortSignal,
  ): Promise<AdapterResult<CredentialPageBody>> {
    const credentials: Credential[] = [];
    for (let offset = 0; offset < count; offset += 1) {
      const address = cursor + offset;
      const response = await this.execute(requestConfig, buildReadUserBody(address, 1), signal);
      const decoded = this.decodeDataEcho(response);
      if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<CredentialPageBody>;
      const data = controllerPayload(decoded.frame.data, requestConfig.node, 24, "87H response");
      const record = decodeUserRecord24(data);
      record.userAddress = address;
      credentials.push(await credentialFromUser(record, data));
    }
    return okResult(pageBody(credentials, cursor + count, rangeEnd));
  }

  public async listUserAliases(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult<UserAliasPageBody>> {
    const unsupported = this.unsupported("listUserAliases");
    if (unsupported) return unsupported as AdapterResult<UserAliasPageBody>;
    try {
      const controller = this.controller(args);
      const start = numeric(args.addressStart);
      const end = numeric(args.addressEnd);
      if (start === undefined || end === undefined) throw new Error("addressStart and addressEnd are required");
      if (start < 0 || end < start || end > 16383) throw new Error("user alias range must be from 0 through 16383");
      const count = end - start + 1;
      if (count > 255) throw new Error("user alias range must contain at most 255 records");
      const requestConfig = { ...this.config, area: controller.area, node: controller.node };
      const response = await this.execute(requestConfig, buildReadUserAliasBody(start, count), signal);
      const decoded = this.decodeDataEcho(response);
      if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<UserAliasPageBody>;
      const data = controllerPayload(decoded.frame.data, requestConfig.node, count * userAliasLength, "2EH alias response");
      const aliases = decodeUserAliases(data, count).map((alias, index) => ({ address: start + index, alias }));
      return okResult({ aliases, cursor: null, done: true });
    } catch (error) {
      return this.operationError(error) as AdapterResult<UserAliasPageBody>;
    }
  }

  public async pullEvents(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult<EventPullBody>> {
    const unsupported = this.unsupported("pullEvents");
    if (unsupported) return unsupported as AdapterResult<EventPullBody>;
    try {
      const controller = this.controller(args);
      const requestConfig = { ...this.config, area: controller.area, node: controller.node };
      const key = `${controller.area}:${controller.node}`;
      const previousCursor = cursorIndex(args.cursor)
        ?? this.eventCursorStore?.eventCursor(key)
        ?? this.eventCursors.get(key);
      const readQueueStatus = async (): Promise<Uint8Array | AdapterResult<EventPullBody>> => {
        const response = await this.execute(requestConfig, buildEventLogQueueStatusBody(), signal);
        const decoded = this.decodeDataEcho(response);
        if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<EventPullBody>;
        try {
          return controllerPayload(decoded.frame.data, requestConfig.node, eventQueueStatusDataLength, "25H queue status", true, true);
        } catch (error) {
          return invalidRecord(errorMessage(error)) as AdapterResult<EventPullBody>;
        }
      };
      const readEventRecords = async (start: number, count: number): Promise<BridgeEvent[] | AdapterResult<EventPullBody>> => {
        const records: BridgeEvent[] = [];
        for (let offset = 0; offset < count; offset += 1) {
          const index = (start + offset) % eventRingCapacity;
          const eventResponse = await this.execute(requestConfig, buildEventLogRecordBody(index), signal);
          const eventFrame = this.decodeFrame(eventResponse, 0);
          if (eventFrame.result.outcome !== CommandOutcome.OK) return eventFrame.result as AdapterResult<EventPullBody>;
          const event = decodeEventRecord(eventFrame.frame);
          records.push(await bridgeEventFromRecord(this.config, controller, event, frameBytes(eventFrame.frame)));
        }
        return records;
      };
      const firstStatus = await readQueueStatus();
      if (!(firstStatus instanceof Uint8Array)) return firstStatus;
      let statusData = firstStatus;
      const queueStatus = decodeEventQueueStatus(statusData);
      const { logCounter: depth, inputPointer, outputPointer } = queueStatus;
      // Confirm a first sample or pointer change before it can create or move
      // a cursor. Stable no-change samples need only one request.
      if (previousCursor === undefined || inputPointer !== previousCursor) {
        const secondStatus = await readQueueStatus();
        if (!(secondStatus instanceof Uint8Array)) return secondStatus;
        if (!sameBytes(statusData.slice(0, eventQueueStatusDataLength), secondStatus.slice(0, eventQueueStatusDataLength))) {
          return invalidRecord("25H queue status was not stable across two reads; cursor was not advanced") as AdapterResult<EventPullBody>;
        }
        statusData = secondStatus;
      }
      // A zero-depth queue normally must not move its pointers. The event log
      // can also be consumed by another poller, though, so a stable pointer
      // change is recoverable by reading the indexed records directly. Those
      // Indexed reads carry the controller's source-node byte and are checked
      // by their decoders before the cursor advances.
      if (depth === 0 && previousCursor !== undefined && inputPointer !== previousCursor) {
        const recoveryDistance = eventRingDistance(previousCursor, inputPointer);
        const recoveryCount = Math.min(recoveryDistance, EVENT_PULL_PAGE_SIZE);
        const pointerAheadUnconfirmed = (): AdapterResult<EventPullBody> => {
          const result: AdapterResult<EventPointerAheadData> = {
            outcome: CommandOutcome.Failed,
            code: "pointer_ahead_unconfirmed",
            detail: `25H queue pointer changed from ${previousCursor} to ${inputPointer} while queue depth was zero, and reading the individual records also failed`,
            data: { previousCursor, observedPointer: inputPointer },
          };
          return result as unknown as AdapterResult<EventPullBody>;
        };
        try {
          const recovery = await readEventRecords(previousCursor, recoveryCount);
          if (!Array.isArray(recovery)) return pointerAheadUnconfirmed();
          const nextCursor = eventRingIndex(previousCursor + recovery.length);
          if (!this.eventCursorStore) this.eventCursors.set(key, nextCursor);
          return okResult({ events: recovery, controller, cursor: String(nextCursor) });
        } catch {
          return pointerAheadUnconfirmed();
        }
      }
      const window = this.resolveEventCursorWindow(args, key, depth, inputPointer, outputPointer);
      const events: BridgeEvent[] = [];
      if (window.wrapped) {
        events.push({ kind: "gap", controller, reason: "log_wrapped", estimatedCount: window.wrappedCount });
      }
      const records = await readEventRecords(window.start, window.count);
      if (!Array.isArray(records)) return records;
      events.push(...records);
      const nextCursor = eventRingIndex(window.start + records.length);
      if (!this.eventCursorStore) this.eventCursors.set(key, nextCursor);
      return okResult({ events, controller, cursor: String(nextCursor) });
    } catch (error) {
      return this.operationError(error) as AdapterResult<EventPullBody>;
    }
  }

  public async controlDoor(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult> {
    const unsupported = this.unsupported("controlDoor");
    if (unsupported) return unsupported;
    void args;
    void signal;
    // 21H is an unsourced relay-command candidate. Keep this closed until
    // Phase 4 validates it against isolated hardware; guessing here opens doors.
    return { outcome: CommandOutcome.Unsupported, code: "command_unsupported" };
  }

  public async commission(args: AdapterArguments, signal?: AbortSignal): Promise<AdapterResult<CommissionResult>> {
    const unsupported = this.unsupported("commission");
    if (unsupported) return unsupported as AdapterResult<CommissionResult>;
    try {
      const controller = this.controller(args);
      const requestConfig = { ...this.config, area: controller.area, node: controller.node };
      // Each subcode has a known echo length. A wrong-size response is not a
      // valid commissioning result; the direct wire owns transport retries.
      const readParameter = async (subCode: number, acceptableLengths?: number[]): Promise<Frame> => {
        const response = await this.execute(requestConfig, buildGetParameterBody(subCode), signal);
        const decoded = this.decodeDataEcho(response);
        if (decoded.result.outcome !== CommandOutcome.OK) throw new ResultError(decoded.result);
        if (acceptableLengths === undefined) return decoded.frame;
        const length = decoded.frame.data.length;
        if (acceptableLengths.some((want) => length === want || length === want + 1)) return decoded.frame;
        throw new ResultError(invalidRecord(`12H sub ${formatByte(subCode)}H returned ${length} data bytes, want ${acceptableLengths.join(" or ")}`));
      };
      const serialFrame = await readParameter(0xfe, [serialParameterLength, serialParameterLength + 1]);
      // Protocol document section 2.2.20: source node at data 00, CPU flash
      // size code at 01-02, then a twelve byte CPU serial number at 03-14. It
      // is binary, not text. This used to decode the whole payload, header
      // bytes included, as a string, which produced an unusable fingerprint.
      // One live controller returns a trailing byte beyond the documented
      // length, so accept that too rather than rejecting the controller.
      let serialPayload: Uint8Array;
      try {
        serialPayload = controllerPayload(serialFrame.data, requestConfig.node, [serialParameterLength, serialParameterLength + 1], "12H sub FEH response");
      } catch (error) {
        throw new ResultError(invalidRecord(errorMessage(error)));
      }
      const serialBytes = serialPayload.slice(2, 2 + controllerSerialLength);
      const serial = Array.from(serialBytes, (value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
      if (serialBytes.length !== controllerSerialLength || /^0*$/.test(serial)) {
        return invalidRecord("12H sub FEH returned an empty serial number") as AdapterResult<CommissionResult>;
      }
      const networkFrame = await readParameter(0x14, [networkParameterLength]);
      // Protocol document section 2.2.13 lays this out as 31 data bytes:
      // options at 00, MAC at 01-06, IPv4 at 07-10, mask at 11-14, gateway at
      // 15-18, TCP port at 19-20, the two DNS addresses at 21-28 and the HTTP
      // port at 29-30. This previously expected 10 bytes and read the IP and
      // MAC off the front, which no controller ever sends, so commissioning
      // could not complete against real hardware.
      let network: Uint8Array;
      try {
        network = controllerPayload(networkFrame.data, requestConfig.node, networkParameterLength, "12H sub 14H response");
      } catch (error) {
        throw new ResultError(invalidRecord(errorMessage(error)));
      }
      const mac = Array.from(network.slice(1, 7), (value) => value.toString(16).padStart(2, "0")).join(":").toUpperCase();
      const ip = Array.from(network.slice(7, 11)).join(".");
      const modeFrame = await readParameter(0x00, [50, 51, 52, 53, 54, 55, 56]);
      const modeData = controllerPayload(modeFrame.data, requestConfig.node, [50, 51, 52, 53, 54, 55, 56], "12H sub 00H response");
      if (modeData.length <= 49) return invalidRecord(`12H sub 00H returned ${modeData.length} bytes, want at least 50`) as AdapterResult<CommissionResult>;
      const capacityModeCode = modeData[49]!;
      // The protocol reference documents mode codes 0x00-0x02 only. Live
      // AR-821EFv5 / C3 controllers return 0x03 here; its full meaning is
      // unsourced, so retain the code and safely leave capacity unmapped.
      const capacityMode = capacityModeFromCode(capacityModeCode);
      const availableFrame = await readParameter(0x15);
      let availableData: Uint8Array;
      try {
        availableData = controllerPayload(availableFrame.data, requestConfig.node, [1, 2, 4], "12H sub 15H response");
      } catch (error) {
        throw new ResultError(invalidRecord(errorMessage(error)));
      }
      if (availableData.length !== 1 && availableData.length !== 2 && availableData.length !== 4) return invalidRecord(`12H sub 15H returned ${availableFrame.data.length} bytes, want one, two, or four value bytes`) as AdapterResult<CommissionResult>;
      const availableUsers = availableData.reduce((total, value) => (total << 8) | value, 0);
      const clockResponse = await this.execute(requestConfig, buildReadClockBody(), signal);
      const clockFrame = this.decodeDataEcho(clockResponse);
      if (clockFrame.result.outcome !== CommandOutcome.OK) return clockFrame.result as AdapterResult<CommissionResult>;
      let controllerTime: Date;
      try {
        controllerTime = decodeControllerClock(controllerPayload(clockFrame.frame.data, requestConfig.node, 7, "24H clock response", true), requestConfig.controllerTimezone);
      } catch (error) {
        throw new ResultError(invalidRecord(errorMessage(error)));
      }
      const bridgeTime = new Date();
      return okResult({ serial, ip, mac, capacityMode, capacityModeCode, availableUsers, controllerTime, bridgeTime, clockDriftMs: controllerTime.getTime() - bridgeTime.getTime() });
    } catch (error) {
      return this.operationError(error) as AdapterResult<CommissionResult>;
    }
  }

  public async syncClock(args: AdapterArguments = {}, signal?: AbortSignal): Promise<AdapterResult> {
    const unsupported = this.unsupported("syncClock");
    if (unsupported) return unsupported;
    try {
      const controller = this.controller(args);
      const requestConfig = { ...this.config, area: controller.area, node: controller.node };
      const readResponse = await this.execute(requestConfig, buildReadClockBody(), signal);
      const readFrame = this.decodeFrame(readResponse, echoData);
      if (readFrame.result.outcome !== CommandOutcome.OK) return readFrame.result;
      const clockData = controllerPayload(readFrame.frame.data, requestConfig.node, 7, "24H clock response", true);
      const desired = optionalTime(args, "time") ?? optionalTime(args, "datetime") ?? new Date();
      const setResponse = await this.execute(requestConfig, buildSetClockBody(desired, requestConfig.controllerTimezone), signal);
      const confirmation = this.confirmWriteAck(setResponse);
      if (confirmation.outcome !== CommandOutcome.OK) return confirmation;
      return okResult({ read: clockData });
    } catch (error) {
      return this.operationError(error);
    }
  }

  /**
   * Read the controller clock and compare it with ours. 24H is read-only, so
   * unlike syncClock this can run on a schedule without touching the site.
   */
  public async readClock(args: AdapterArguments = {}, signal?: AbortSignal): Promise<AdapterResult<ClockReading>> {
    const unsupported = this.unsupported("readClock");
    if (unsupported) return unsupported as AdapterResult<ClockReading>;
    try {
      const controller = this.controller(args);
      const requestConfig = { ...this.config, area: controller.area, node: controller.node };
      const response = await this.execute(requestConfig, buildReadClockBody(), signal);
      const decoded = this.decodeDataEcho(response);
      if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result as AdapterResult<ClockReading>;
      const controllerTime = decodeControllerClock(controllerPayload(decoded.frame.data, requestConfig.node, 7, "24H clock response", true), requestConfig.controllerTimezone);
      const bridgeTime = new Date();
      return okResult({ controllerTime, bridgeTime, clockDriftMs: controllerTime.getTime() - bridgeTime.getTime() });
    } catch (error) {
      return this.operationError(error) as AdapterResult<ClockReading>;
    }
  }

  /** Read each controller once. Different controllers use different sockets,
   * so these independent 24H requests may run concurrently. */
  public async readClockBatch(targets: Array<{ area: number; node: number }>, signal?: AbortSignal): Promise<AdapterResult<{ readings: Array<{ area: number; node: number; controllerTime: Date; bridgeTime: Date; clockDriftMs: number }> }>> {
    const unsupported = this.unsupported("readClockBatch");
    if (unsupported) return unsupported as AdapterResult<{ readings: Array<{ area: number; node: number; controllerTime: Date; bridgeTime: Date; clockDriftMs: number }> }>;
    if (targets.length === 0) return okResult({ readings: [] });
    try {
      const readings = await Promise.all(targets.map(async (target) => {
        const result = await this.readClock({ controller: target }, signal);
        if (result.outcome !== CommandOutcome.OK || result.data === undefined) throw new ResultError(result);
        return { area: target.area, node: target.node, ...result.data };
      }));
      return okResult({ readings });
    } catch (error) {
      return this.operationError(error) as AdapterResult<{ readings: Array<{ area: number; node: number; controllerTime: Date; bridgeTime: Date; clockDriftMs: number }> }>;
    }
  }

  public async probe(args: AdapterArguments = {}, signal?: AbortSignal): Promise<AdapterResult> {
    const unsupported = this.unsupported("probe");
    if (unsupported) return unsupported;
    try {
      const name = typeof args.probe === "string" ? args.probe : "";
      if (name === "controllerStatus") {
        const discovery = await this.discover(args, signal);
        if (discovery.outcome !== CommandOutcome.OK) return discovery;
        return okResult({ probe: name, ...discovery.data });
      } else if (name === "clock") {
        const clock = await this.readClock(args, signal);
        if (clock.outcome !== CommandOutcome.OK) return clock as AdapterResult;
        return okResult({ probe: name, ...clock.data });
      } else {
        throw new Error(`unknown probe ${JSON.stringify(name)}`);
      }
    } catch (error) {
      return this.operationError(error);
    }
  }

  public async discover(args: AdapterArguments = {}, signal?: AbortSignal): Promise<AdapterResult<{ controllers: ControllerHealth[] }>> {
    const unsupported = this.unsupported("discover");
    if (unsupported) return unsupported as AdapterResult<{ controllers: ControllerHealth[] }>;
    try {
      const requested = controllersFromArguments(args);
      const controllers = await Promise.all(requested.map(async (controller): Promise<ControllerHealth> => {
        try {
          const response = await this.execute(controller, buildGetParameterBody(0xfe), signal);
          const decoded = this.decodeDataEcho(response);
          if (decoded.result.outcome !== CommandOutcome.OK) return { ...controller, online: false };
          // A 12H identity read is the safe direct reachability probe. It also
          // checks that a response belongs to the requested controller.
          controllerPayload(decoded.frame.data, controller.node, [serialParameterLength, serialParameterLength + 1], "12H reachability response");
          return { ...controller, online: true, lastSeenAt: new Date() };
        } catch {
          return { ...controller, online: false };
        }
      }));
      return okResult({ controllers });
    } catch (error) {
      return this.operationError(error) as AdapterResult<{ controllers: ControllerHealth[] }>;
    }
  }

  private async writeUserCredential(controller: Controller, desired: AdapterArguments, address: number, tagUid: Uint8Array, bitmap: { group1: number; group2: number }, accessMode: AccessMode, zone: number, signal?: AbortSignal): Promise<AdapterResult> {
    const validUntil = optionalTime(desired, "validUntil");
    const level = "level" in desired ? integerArgument(desired, "level", 0, 0, 3) : 0;
    // A live comparison against this site's own pre-existing 84H cards (all of
    // which open their door) found every one carries a real year/month/day --
    // 2079-12-31 for the open-ended ones -- and fingerprintOmittedAfterCard
    // set, even though enableExpireCheck is off. A record with an all-zero
    // date and that bit clear (what the protocol doc implies "no expiry"
    // should look like) read back byte-identical apart from those two fields
    // and was silently denied with no event logged; copying the working
    // fields exactly, tag swapped, opened the door. Zero-date is apparently
    // not a safe "don't care" on this firmware.
    const record: UserRecord = {
      userAddress: address,
      tagUid,
      pinCode: 0,
      mode: buildMode({ accessMode, patrol: false, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: true, enableExpireCheck: validUntil !== undefined, guest: false, passwordChangeAllowed: false }),
      zone,
      group1: bitmap.group1,
      group2: bitmap.group2,
      year: validUntil ? protocolYear(validUntil, "validUntil") : openEndedUserRecordYear,
      month: validUntil ? validUntil.getMonth() + 1 : 12,
      day: validUntil ? validUntil.getDate() : 31,
      level,
      option: 0,
      reserved: new Uint8Array(3),
    };
    const response = await this.execute(controller, buildSetUserBody(record), signal);
    const confirmation = this.confirmWriteAck(response);
    if (confirmation.outcome !== CommandOutcome.OK) return confirmation;
    return okResult({ address, mode: "84H" });
  }

  private async writeGuestCredential(controller: Controller, desired: AdapterArguments, address: number, tagUid: Uint8Array, bitmap: { group1: number; group2: number }, accessMode: AccessMode, zone: number, signal?: AbortSignal): Promise<AdapterResult> {
    const begin = optionalTime(desired, "validFrom") ?? new Date();
    const end = optionalTime(desired, "validUntil") ?? new Date(2099, 11, 31, 23, 59);
    if (end.getTime() <= begin.getTime()) throw new Error("validUntil must be after validFrom");
    const record: GuestAccessRecord = {
      userAddress: address,
      tagUid,
      pinCode: 0,
      mode: buildGuestAccessMode({ accessMode, patrol: false, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: false, enableExpireCheck: true, checkBeginAndEndTime: true, passwordChangeAllowed: false }),
      zone,
      group1: bitmap.group1,
      group2: bitmap.group2,
      beginYear: protocolYear(begin, "validFrom"),
      beginMonth: begin.getMonth() + 1,
      beginDay: begin.getDate(),
      beginHour: begin.getHours(),
      beginMinute: begin.getMinutes(),
      endYear: protocolYear(end, "validUntil"),
      endMonth: end.getMonth() + 1,
      endDay: end.getDate(),
      endHour: end.getHours(),
      endMinute: end.getMinutes(),
      lift: new Uint8Array(4),
    };
    const response = await this.execute(controller, buildSetGuestAccessBody(record), signal);
    const confirmation = this.confirmWriteAck(response);
    if (confirmation.outcome !== CommandOutcome.OK) return confirmation;
    return okResult({ address, mode: "8BH" });
  }

  private async execute(target: Controller, body: Uint8Array, signal?: AbortSignal): Promise<Frame> {
    try {
      return await this.wire.send({ area: target.area, node: target.node }, body, signal);
    } catch (error) {
      if (error instanceof SoyalWireError) throw new OperationError("transport_error", error.message);
      throw new OperationError("transport_error", errorMessage(error));
    }
  }

  private decodeDataEcho(response: Frame): DecodedFrameResult {
    const decoded = this.decodeFrame(response, 0);
    if (decoded.result.outcome !== CommandOutcome.OK) return decoded;
    if (decoded.frame.command !== echoData) {
      return { ...decoded, result: classifyEchoCode(decoded.frame.command) };
    }
    return decoded;
  }

  private decodeFrame(frame: Frame, expectedCommand: number): DecodedFrameResult {
    try {
      if (expectedCommand !== 0 && frame.command !== expectedCommand) {
        return { frame, result: classifyEchoCode(frame.command) };
      }
      return { frame, result: okResult() };
    } catch (error) {
      return { frame, result: invalidFrame(errorMessage(error)) };
    }
  }

  private confirmWriteAck(response: Frame): AdapterResult {
    const decoded = this.decodeFrame(response, 0);
    if (decoded.result.outcome !== CommandOutcome.OK) return decoded.result;
    // The embedded controller frame must be 04H (ACK); 03H only means the
    // controller echoed request data and does not prove persistence.
    if (decoded.frame.command === echoAck) return okResult();
    if (decoded.frame.command === echoData) {
      return {
        outcome: CommandOutcome.Rejected,
        code: "device_rejected",
        detail: "controller returned echo 0x03 (request data), not write ACK 0x04",
      };
    }
    return classifyEchoCode(decoded.frame.command);
  }

  private resolveEventCursorWindow(args: AdapterArguments, key: string, depth: number, inputPointer: number, outputPointer: number): EventCursorWindow {
    let cursorValue = cursorIndex(args.cursor);
    if (cursorValue === undefined) cursorValue = this.eventCursorStore?.eventCursor(key);
    if (cursorValue === undefined) cursorValue = this.eventCursors.get(key);
    const hasCursor = cursorValue !== undefined;
    let start = cursorValue ?? outputPointer;
    const cursorWrapped = hasCursor && !eventCursorInWindow(start, inputPointer, outputPointer);
    const pointerWrapped = !hasCursor && (inputPointer < outputPointer || depth >= eventRingCapacity);
    const wrapped = cursorWrapped || pointerWrapped;
    // A stale/corrupt pointer can make the modulo distance look enormous.
    // The controller can only have lost at most the current ring depth, so
    // never emit a fabricated multi-million-event gap.
    const wrappedCount = pointerWrapped
      ? Math.max(1, eventRingCapacity - depth)
      : cursorWrapped
        ? Math.min(eventRingDistance(start, outputPointer), depth)
        : 0;
    if (wrapped) start = outputPointer;
    const distance = eventRingDistance(start, inputPointer);
    const fullRingAtSamePointer = depth > 0 && inputPointer === outputPointer && (!hasCursor || cursorValue !== inputPointer);
    return {
      start,
      count: fullRingAtSamePointer
        ? Math.min(depth, EVENT_PULL_PAGE_SIZE)
        : Math.min(distance, depth, EVENT_PULL_PAGE_SIZE),
      wrapped,
      wrappedCount,
    };
  }

  private controller(args: AdapterArguments): Controller {
    const defaultController = { area: this.config.area, node: this.config.node };
    if (!isJsonObject(args.controller)) return defaultController;
    return {
      area: integerArgument(args.controller, "area", defaultController.area, 0, maximumArea),
      node: integerArgument(args.controller, "node", defaultController.node, 1, maximumNode),
    };
  }

  private address(args: AdapterArguments, fieldName: string, maximum: number): number {
    const value = numeric(args[fieldName]);
    if (value === undefined || value < 0 || value > maximum) throw new Error(`${fieldName} must be an integer from 0 through ${maximum}`);
    return value;
  }

  private credentialRange(args: AdapterArguments): { start: number; end: number; controller: Controller } {
    const controller = this.controller(args);
    const start = numeric(args.addressStart);
    const end = numeric(args.addressEnd);
    if (start === undefined) throw new Error("addressStart is required");
    if (end === undefined) throw new Error("addressEnd is required");
    if (start < 0 || end < start || end > 16383) throw new Error("credential range must be from 0 through 16383");
    return { start, end, controller };
  }

  private unsupported(capability: string): AdapterResult | undefined {
    if (this.capabilities.has(capability)) return undefined;
    return { outcome: CommandOutcome.Unsupported, code: "capability_unsupported", detail: `SOYAL site does not support ${capability}` };
  }

  private operationError(error: unknown): AdapterResult {
    if (error instanceof ResultError) return error.result;
    if (error instanceof OperationError) {
      return { outcome: error.code === "device_rejected" ? CommandOutcome.Rejected : CommandOutcome.Failed, code: error.code, detail: error.message };
    }
    return failedResult(errorMessage(error));
  }
}

interface DecodedFrameResult {
  frame: Frame;
  result: AdapterResult;
}

interface EventCursorWindow {
  start: number;
  count: number;
  wrapped: boolean;
  wrappedCount: number;
}

class OperationError extends Error {
  public constructor(
    public readonly code: "transport_error" | "invalid_response" | "device_rejected",
    message: string,
  ) {
    super(message);
    this.name = "OperationError";
  }
}

class ResultError extends Error {
  public constructor(public readonly result: AdapterResult) {
    super(result.detail ?? "SOYAL operation failed");
    this.name = "ResultError";
  }
}

/**
 * Extract a direct-controller response payload.
 *
 * This validates a leading source-node byte the same way for every caller:
 * strip it when present and matching, reject it when present and wrong. A
 * genuine mismatch here still means the response is not trustworthy -- for
 * most commands (queue status, 12H parameters, credential reads) byte 0 is
 * either the expected prefix or real payload data, never a benign identity
 * quirk, so silently stripping it on a mismatch shifts every following byte
 * and decodes garbage that still "looks like" a valid value (e.g. queue
 * counters). That happened live on 2026-09-16: a stripped-on-mismatch queue
 * status read produced a stable but wrong multi-million event-count gap,
 * repeating every poll because the misdecode was deterministic. The ONE
 * place a mismatch is a known, benign device quirk is decoding individual
 * 25H event records, where the leading byte is the device's own stored
 * node identity rather than a reply-correlation prefix -- that call site
 * (in pullEvents' readEventRecords) does not use this helper for that
 * check and never did after 2026-09-15's direct-IP fix; keep it that way
 * rather than relaxing this shared helper again.
 */
function controllerPayload(data: Uint8Array, sourceNode: number, expectedLength: number | number[], name: string, allowTrailingSourceData = false, preserveTrailingData = false): Uint8Array {
  const lengths = Array.isArray(expectedLength) ? expectedLength : [expectedLength];
  if (data.length > 0 && data[0] === sourceNode) {
    const sourceDataLength = data.length - 1;
    const matchingLength = lengths.find((length) => allowTrailingSourceData ? sourceDataLength >= length : sourceDataLength === length);
    if (matchingLength !== undefined) return preserveTrailingData ? data.slice(1) : data.slice(1, matchingLength + 1);
  }
  // A payload exactly one byte longer than expected, with a leading byte
  // that does not match the dialed node, is a source-node prefix naming the
  // wrong controller: reject it before the generic trailing-data-allowed
  // branch below gets a chance to accept it anyway. Checking this AFTER that
  // branch, as a stale version of this function did, is what let a
  // mismatched 25H queue-status reply through on 2026-09-16: it was exactly
  // expectedLength+1 bytes, `allowTrailingSourceData` is true for that call
  // site, so `data.length >= length` was satisfied and the full mismatched
  // payload -- wrong leading byte included -- was returned unstripped. That
  // decoded a stable but enormous fake input pointer, which the (correctly
  // bounded) wrap logic then chased forever, fabricating thousands of huge
  // "gap" rows in production before this was caught and reverted.
  if (data.length > 0 && data[0] !== sourceNode
    && lengths.some((length) => data.length === length + 1)) {
    throw new OperationError(
      "invalid_response",
      `${name} carries data from node ${data[0]} but the request was sent to node ${sourceNode}`,
    );
  }
  if (lengths.includes(data.length)) return data;
  const matchingLength = lengths.find((length) => allowTrailingSourceData && data.length >= length);
  if (matchingLength !== undefined) return preserveTrailingData ? data : data.slice(0, matchingLength);
  const wanted = lengths.join(" or ");
  throw new Error(`${name} has ${data.length} data bytes, want ${wanted}, with an optional source-node byte`);
}

export function classifyEchoCode(code: number): AdapterResult {
  if (code === echoAck || code === echoData) return okResult();
  const description = echoCodeDescriptions[code];
  if (description) return { outcome: CommandOutcome.Rejected, code: "device_rejected", detail: `controller echo 0x${formatByte(code)}: ${description}` };
  return invalidFrame(`unexpected controller echo code 0x${formatByte(code)}`);
}

const echoCodeDescriptions: Readonly<Record<number, string>> = {
  5: "command unacknowledged (NACK)",
  6: "authentication failed",
  7: "no tag presented",
  8: "user not logged in",
  9: "CRC8 check error",
  12: "communication level rejected",
  13: "TCP timeout",
  14: "TCP keep-alive",
};

function desiredArguments(args: AdapterArguments): AdapterArguments {
  return isJsonObject(args.desired) ? args.desired : args;
}

function stringArgument(values: AdapterArguments, ...names: string[]): string {
  for (const name of names) {
    if (typeof values[name] === "string" && values[name].trim()) return values[name] as string;
  }
  throw new Error(`${names.join(" or ")} is required`);
}

function desiredAccessMode(values: AdapterArguments): AccessMode {
  if (values.accessMode === undefined) return AccessMode.CardOnly;
  if (typeof values.accessMode !== "string") throw new Error("accessMode must be a string");
  switch (values.accessMode.trim().toLowerCase()) {
    case "invalid": return AccessMode.Invalid;
    case "card-only": return AccessMode.CardOnly;
    case "card-or-pin": return AccessMode.CardOrPin;
    case "card-and-pin": return AccessMode.CardAndPin;
    default: throw new Error("accessMode must be one of invalid, card-only, card-or-pin, or card-and-pin");
  }
}

function doorNumbers(values: AdapterArguments): { group1: number; group2: number } {
  const raw = values.doorNumbers ?? values.doors;
  let doors: number[];
  if (typeof raw === "string") {
    doors = raw.split(",").map((value) => Number(value.trim()));
  } else if (Array.isArray(raw)) {
    doors = raw.map((value) => numeric(value) ?? Number.NaN);
  } else {
    throw new Error("doorNumbers is required");
  }
  let bitmap = { group1: 0, group2: 0 };
  for (const door of doors) bitmap = setDoorBitmapForAdapter(bitmap, door);
  return bitmap;
}

function setDoorBitmapForAdapter(bitmap: { group1: number; group2: number }, door: number): { group1: number; group2: number } {
  if (!Number.isInteger(door) || door < 1 || door > 16) throw new Error(`invalid SOYAL door number ${door}: want a value from 1 through 16`);
  if (door <= 8) return { group1: bitmap.group1, group2: bitmap.group2 | (1 << (door - 1)) };
  return { group1: bitmap.group1 | (1 << (door - 9)), group2: bitmap.group2 };
}

function optionalTime(values: AdapterArguments, fieldName: string): Date | undefined {
  const value = values[fieldName];
  if (value === undefined || value === null) return undefined;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new Error(`${fieldName} must be a valid time`);
    return value;
  }
  if (typeof value !== "string") throw new Error(`${fieldName} must be a time string`);
  const text = value.trim();
  const localMatch = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(text);
  const parsed = localMatch
    ? new Date(Number(localMatch[1]), Number(localMatch[2]) - 1, Number(localMatch[3]), Number(localMatch[4] ?? 0), Number(localMatch[5] ?? 0), Number(localMatch[6] ?? 0))
    : new Date(text);
  if (Number.isNaN(parsed.getTime())) throw new Error(`${fieldName} must be an RFC3339 or YYYY-MM-DD HH:MM time`);
  return parsed;
}

function integerArgument(values: AdapterArguments, fieldName: string, fallback: number, minimum: number, maximum: number): number {
  const value = values[fieldName];
  if (value === undefined || value === null) return fallback;
  const parsed = numeric(value);
  if (parsed === undefined || parsed < minimum || parsed > maximum) throw new Error(`${fieldName} must be an integer from ${minimum} through ${maximum}`);
  return parsed;
}

function numeric(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : undefined;
  if (typeof value === "string" && /^[-+]?\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

function validateNode(node: number, fieldName: string): void {
  if (!Number.isInteger(node) || node < 1 || node > maximumNode) {
    throw new Error(`SOYAL ${fieldName} must be an integer from 1 through ${maximumNode}`);
  }
}

function cursorAddress(args: AdapterArguments, fallback: number): number {
  if (args.cursor === undefined || args.cursor === null) return fallback;
  const value = numeric(args.cursor);
  if (value === undefined) throw new Error("cursor must be a numeric address");
  return value;
}

function cursorIndex(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  const parsed = numeric(value);
  if (parsed === undefined || parsed < 0 || parsed > 0xffffff) throw new Error("cursor must be a 24-bit index");
  return parsed;
}

function protocolYear(value: Date, fieldName: string): number {
  const year = value.getFullYear();
  if (year < 2000 || year > 2099) throw new Error(`${fieldName} must be from 2000 through 2099 for the protocol's two-digit year field`);
  return year - 2000;
}

async function credentialFromUser(record: UserRecord, raw: Uint8Array): Promise<Credential> {
  const mode = record.mode & 0x04;
  return {
    address: record.userAddress,
    tagUid: uidString(record.tagUid) ?? null,
    doors: doorsFromBitmap(record.group1, record.group2),
    validFrom: null,
    validUntil: mode ? new Date(2000 + record.year, record.month - 1, record.day, 23, 59, 59) : null,
    actualHash: await hashBytes(raw),
  };
}

async function credentialFromGuest(record: GuestAccessRecord, raw: Uint8Array): Promise<Credential> {
  return {
    address: record.userAddress,
    tagUid: uidString(record.tagUid) ?? null,
    doors: doorsFromBitmap(record.group1, record.group2),
    validFrom: new Date(2000 + record.beginYear, record.beginMonth - 1, record.beginDay, record.beginHour, record.beginMinute),
    validUntil: new Date(2000 + record.endYear, record.endMonth - 1, record.endDay, record.endHour, record.endMinute),
    actualHash: await hashBytes(raw),
  };
}

// The identity a journal row is deduplicated on. It is deliberately content
// based rather than index based, so the same physical swipe collapses to one
// row regardless of which event ingestion path delivered it.
export function eventIdentity(parts: {
  siteId: string;
  area: number;
  node: number;
  deviceTime: Date;
  userAddress: number;
  functionCode: number;
  tagUid: string;
}): string {
  return `${parts.siteId}:${parts.area}:${parts.node}:${parts.deviceTime.toISOString()}:${parts.userAddress}:${parts.functionCode}:${parts.tagUid}`;
}

export async function eventDedupeKey(parts: Parameters<typeof eventIdentity>[0]): Promise<string> {
  return hashBytes(new TextEncoder().encode(eventIdentity(parts)));
}

async function hashBytes(value: Uint8Array): Promise<string> {
  const bytes = new Uint8Array(value.length);
  bytes.set(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function pageBody(credentials: Credential[], cursor: number, end: number): CredentialPageBody {
  return cursor <= end ? { credentials, cursor: String(cursor), done: false } : { credentials, cursor: null, done: true };
}

async function bridgeEventFromRecord(config: ResolvedSoyalAdapterConfig, controller: Controller, event: EventRecord, raw: Uint8Array): Promise<BridgeEvent> {
  const deviceTime = eventTime(event, config.controllerTimezone);
  const timeZone = config.controllerTimezone.trim() && config.controllerTimezone.trim().toLowerCase() !== "local"
    ? config.controllerTimezone.trim()
    : Intl.DateTimeFormat().resolvedOptions().timeZone ?? "local";
  const identity = eventIdentity({
    siteId: config.siteId,
    area: controller.area,
    node: controller.node,
    deviceTime,
    userAddress: event.userAddress,
    functionCode: event.functionCode,
    tagUid: formatUid(event.tagUid),
  });
  return {
    kind: "event",
    controller,
    deviceSourceNode: event.sourceNode,
    door: event.doorNumber,
    functionCode: event.functionCode,
    userAddress: event.userAddress,
    tagUid: formatUid(event.tagUid),
    deviceTime,
    deviceTimezone: timeZone,
    bridgeReceivedAt: new Date(),
    dedupeKey: await hashBytes(new TextEncoder().encode(identity)),
    raw: Array.from(raw, (value) => value.toString(16).padStart(2, "0")).join(""),
  };
}

function formatUid(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function eventCursorInWindow(cursor: number, inputPointer: number, outputPointer: number): boolean {
  if (cursor < 0 || inputPointer < 0 || outputPointer < 0
    || cursor >= eventRingCapacity || inputPointer >= eventRingCapacity || outputPointer >= eventRingCapacity) return false;
  if (cursor === inputPointer) return true;
  const window = eventRingDistance(outputPointer, inputPointer);
  const distance = eventRingDistance(outputPointer, cursor);
  return distance < window;
}

function eventRingIndex(value: number): number {
  return ((value % eventRingCapacity) + eventRingCapacity) % eventRingCapacity;
}

function eventRingDistance(start: number, end: number): number {
  return eventRingIndex(end - start);
}

function capacityModeFromCode(code: number): number | null {
  if (code === 0) return 16384;
  if (code === 1) return 32768;
  if (code === 2) return 65535;
  return null;
}

export function decodeControllerClock(data: Uint8Array, timeZone?: string): Date {
  if (data.length !== 7) throw new Error(`24H clock response has ${data.length} data bytes, want 7`);
  return controllerWallClockToDate({
    year: 2000 + data[6]!,
    month: data[5]!,
    day: data[4]!,
    hour: data[2]!,
    minute: data[1]!,
    second: data[0]!,
  }, timeZone);
}

function controllersFromArguments(args: AdapterArguments): Controller[] {
  if (Array.isArray(args.controllers)) {
    return args.controllers.map((value, index) => controllerValue(value, `controllers[${index}]`));
  }
  if (isJsonObject(args.controller)) return [controllerValue(args.controller, "controller")];
  throw new Error("controllers is required; direct discovery probes the caller-provided controller list");
}

function controllerValue(value: unknown, fieldName: string): Controller {
  if (!isJsonObject(value)) throw new Error(`${fieldName} must contain area and node`);
  const area = numeric(value.area);
  const node = numeric(value.node);
  if (area === undefined || area < 0 || area > maximumArea) throw new Error(`${fieldName}.area must be an integer from 0 through ${maximumArea}`);
  if (node === undefined || node < 1 || node > maximumNode) throw new Error(`${fieldName}.node must be an integer from 1 through ${maximumNode}`);
  return { area, node };
}

function okResult<T>(data?: T): AdapterResult<T> {
  return data === undefined ? { outcome: CommandOutcome.OK } : { outcome: CommandOutcome.OK, data };
}

function failedResult(detail: string): AdapterResult {
  return { outcome: CommandOutcome.Failed, code: "invalid_request", detail };
}

function invalidRecord(detail: string): AdapterResult {
  return { outcome: CommandOutcome.Failed, code: "invalid_record", detail };
}

function invalidFrame(detail: string): AdapterResult {
  return { outcome: CommandOutcome.Failed, code: "invalid_frame", detail };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function formatByte(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

function frameBytes(frame: Frame): Uint8Array {
  const bytes = new Uint8Array(2 + frame.data.length);
  bytes[0] = frame.did;
  bytes[1] = frame.command;
  bytes.set(frame.data, 2);
  return bytes;
}

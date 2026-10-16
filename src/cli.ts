import {
  CommandOutcome,
  SoyalAdapter,
  type AdapterResult,
  type SoyalAdapterConfig,
} from "./adapter";
import {
  buildEraseUserRangeBody,
  buildEventLogQueueStatusBody,
  buildEventLogRecordBody,
  buildGetParameterBody,
  buildHostingPollBody,
  buildReadClockBody,
  buildReadUserAliasBody,
  buildReadUserBody,
  buildSetClockBody,
  buildSetUserBody,
} from "./command";
import { SoyalDirectTransport } from "./direct-transport";
import { decodeEventRecord, eventTime, type EventRecord } from "./event";
import { type Frame } from "./frame";
import {
  AccessMode,
  buildGuestAccessMode,
  buildMode,
  buildReadGuestAccessBody,
  buildSetGuestAccessBody,
  decodeGuestAccessRecord,
  decodeUserAliases,
  decodeUserRecord24,
  doorsFromBitmap,
  guestAccessRecordLength,
  setDoorBitmap,
  uidBytes,
  uidString,
  userAliasLength,
  type GuestAccessRecord,
  type UserRecord,
} from "./record";
import type { SoyalWire, WireTarget } from "./wire";

type JsonObject = Record<string, unknown>;

const defaultPort = 1621;
const defaultArea = 0;
const defaultNode = 1;
const defaultTimeoutMs = 30_000;
const maximumNode = 254;
const maximumArea = 15;
const maximumUserAddress = 16_383;
const maximumGuestAddress = 0xffffff;
const writeCommands = new Set(["user-write", "guest-write", "user-erase", "clock"]);
const knownOptions = new Set([
  "ip", "port", "area", "node", "did", "timeout", "timeout-ms",
  "count", "doors", "expiry", "begin", "end", "mode", "level", "zone",
  "yes", "dry-run", "json", "help",
]);
const booleanOptions = new Set(["yes", "dry-run", "json", "help"]);

export interface ParsedArguments {
  command: string;
  options: Record<string, string>;
  flags: Set<string>;
  positionals: string[];
}

export interface CliConnectionConfig {
  ip: string;
  port: number;
  area: number;
  node: number;
  timeoutMs: number;
}

export interface CliDependencies {
  transport?: SoyalWire;
  adapter?: SoyalAdapter;
  now?: () => Date;
}

export interface CliWriter {
  write(value: string): unknown;
}

interface DirectRequest {
  label: string;
  body: Uint8Array;
}

export const cliHelp = `SOYAL direct-controller CLI

Usage:
  bun run soyal -- <command> [options]

The CLI connects directly to one controller. It does not use 701Server or its
JSON protocol. --ip is required whenever a connection is opened.

Read-only commands:
  status                                       Read controller identity and health data.
  get-parameter <sub-code>                    Read one 12H parameter.
  rtc-read                                     Read controller clock and local drift.
  user-read <address> [--count <count>]       Read 87H user records.
  alias-read <address> [--count <count>]      Read 2EH user aliases.
  guest-read <address>                         Read one 8BH guest record.
  log-status                                   Read 25H event-queue status.
  log-read <index>                             Read one indexed 25H event.
  poll                                         Send one 18H request, not active hosting.
  raw <command-body-hex>                      Send [command, ...data] and parse the reply.

Writes (all require --yes):
  user-write <address> <uid> --doors <list> --expiry <date>
  guest-write <address> <uid> --doors <list> --begin <time> --end <time>
  user-erase <address>
  clock <datetime>

Connection options:
  --ip <address>                              Controller IP (required).
  --port <port>                               Controller TCP port, default 1621.
  --area <number>                             Area, default 0.
  --node <number>, --did <number>              Controller DID, default 1.
  --timeout <milliseconds>                    Response timeout, default 30000.
  --dry-run                                    Print target and direct request only.
  --json                                       Emit compact JSON.
  --yes                                        Confirm a controller write.

Credential options:
  --count <number>                             Number of records, default 1.
  --doors 1,2,3                                Door numbers 1 through 16.
  --expiry YYYY-MM-DD                          Last allowed date for user-write.
  --begin YYYY-MM-DD\\ HH:MM                   Guest-write start time.
  --end YYYY-MM-DD\\ HH:MM                     Guest-write end time.
  --mode invalid|card-only|card-or-pin|card-and-pin
  --level <0..3> --zone <0..63>

Before a write, the CLI prints the target IP, node, and affected address. Direct
CLI writes do not perform the application worker's read-back.
`;

export function parseArguments(argumentsList: string[]): ParsedArguments {
  const parsed: ParsedArguments = { command: "", options: {}, flags: new Set(), positionals: [] };
  for (let index = 0; index < argumentsList.length; index += 1) {
    const token = argumentsList[index];
    if (token === "-h") {
      parsed.flags.add("help");
      continue;
    }
    if (token === "--") {
      parsed.positionals.push(...argumentsList.slice(index + 1));
      break;
    }
    if (token.startsWith("--")) {
      const rawOption = token.slice(2);
      const equalsIndex = rawOption.indexOf("=");
      const optionName = equalsIndex >= 0 ? rawOption.slice(0, equalsIndex) : rawOption;
      if (!knownOptions.has(optionName)) throw new Error(`unknown option --${optionName}`);
      if (booleanOptions.has(optionName)) {
        if (equalsIndex >= 0) throw new Error(`--${optionName} does not accept a value`);
        parsed.flags.add(optionName);
        continue;
      }
      let value = equalsIndex >= 0 ? rawOption.slice(equalsIndex + 1) : undefined;
      if (value === undefined) {
        const nextToken = argumentsList[index + 1];
        if (nextToken === undefined || nextToken.startsWith("--")) throw new Error(`--${optionName} requires a value`);
        index += 1;
        value = nextToken;
      }
      parsed.options[optionName] = value;
      continue;
    }
    if (parsed.command === "") parsed.command = token;
    else parsed.positionals.push(token);
  }
  if (parsed.command === "") parsed.command = "help";
  if (parsed.command === "help") parsed.flags.add("help");
  return parsed;
}

export function resolveConnection(
  parsed: ParsedArguments,
  environment: Record<string, string | undefined> = process.env,
): CliConnectionConfig {
  const ip = parsed.options.ip ?? environment.SOYAL_IP;
  if (ip === undefined || ip.trim() === "") throw new Error("--ip is required (or set SOYAL_IP)");
  const port = parsed.options.port ?? environment.SOYAL_CONTROLLER_PORT ?? String(defaultPort);
  const area = parsed.options.area ?? environment.SOYAL_AREA ?? String(defaultArea);
  const node = parsed.options.node ?? parsed.options.did ?? environment.SOYAL_NODE ?? String(defaultNode);
  const timeout = parsed.options.timeout ?? parsed.options["timeout-ms"] ?? environment.SOYAL_TIMEOUT_MS ?? String(defaultTimeoutMs);
  return {
    ip: ip.trim(),
    port: integerValue(port, "port", 1, 65_535),
    area: integerValue(area, "area", 0, maximumArea),
    node: integerValue(node, "node", 1, maximumNode),
    timeoutMs: integerValue(timeout, "timeout", 1, 300_000),
  };
}

export async function runCli(
  argumentsList: string[],
  output: CliWriter = process.stdout,
  errorOutput: CliWriter = process.stderr,
  dependencies: CliDependencies = {},
): Promise<number> {
  let parsed: ParsedArguments = { command: "", options: {}, flags: new Set(), positionals: [] };
  try {
    parsed = parseArguments(argumentsList);
    if (parsed.flags.has("help")) {
      writeText(output, cliHelp);
      return 0;
    }
    if (!supportedCommands.has(parsed.command)) throw new Error(`unknown command ${parsed.command}`);
    const connection = resolveConnection(parsed);
    const requests = buildRequests(parsed, connection);
    const writeRequest = writeCommands.has(parsed.command) || requests.some((request) => isWriteBody(request.body));
    if (parsed.flags.has("dry-run")) {
      writeValue(output, {
        target: targetOutput(connection),
        requests: requests.map((request) => ({ label: request.label, body: toHex(request.body) })),
      }, parsed.flags.has("json"));
      if (writeRequest && !parsed.flags.has("yes")) {
        throw new Error(`${parsed.command} refused: re-run with --yes to confirm this controller write`);
      }
      return 0;
    }
    if (writeRequest && !parsed.flags.has("yes")) {
      throw new Error(`${parsed.command} refused: --yes is required before a controller write can be sent`);
    }
    const transport = dependencies.transport ?? createDirectTransport(connection);
    const adapter = dependencies.adapter ?? new SoyalAdapter(adapterConfig(parsed, connection), transport);
    if (writeRequest) {
      writeText(errorOutput, `target ip=${connection.ip} node=${connection.node} address=${writeAddress(parsed, requests)}\n`);
    }
    const result = await executeCommand(parsed, connection, requests, adapter, transport, dependencies.now ?? (() => new Date()));
    writeValue(output, result, parsed.flags.has("json"));
    await transport.close?.();
    return 0;
  } catch (error) {
    writeError(errorOutput, error, parsed.flags.has("json"));
    return 1;
  }
}

const supportedCommands = new Set([
  "status", "get-parameter", "rtc-read", "user-read", "alias-read", "guest-read",
  "log-status", "log-read", "poll", "user-write", "guest-write", "user-erase", "clock", "raw",
]);

function createDirectTransport(connection: CliConnectionConfig): SoyalDirectTransport {
  return new SoyalDirectTransport({
    endpoint: () => ({ host: connection.ip, port: connection.port }),
    timeoutMs: connection.timeoutMs,
  });
}

function adapterConfig(parsed: ParsedArguments, connection: CliConnectionConfig): SoyalAdapterConfig {
  return {
    siteId: "soyal-cli",
    area: connection.area,
    node: connection.node,
    nodeStart: connection.node,
    nodeEnd: connection.node,
    credentialWriteMode: parsed.command === "guest-write" ? "8BH" : "84H",
    controllerTimezone: "Asia/Taipei",
  };
}

function buildRequests(parsed: ParsedArguments, connection: CliConnectionConfig): DirectRequest[] {
  switch (parsed.command) {
    case "status":
      return [
        request("serial", buildGetParameterBody(0xfe)),
        request("network", buildGetParameterBody(0x14)),
        request("clock", buildReadClockBody()),
        request("event-queue", buildEventLogQueueStatusBody()),
      ];
    case "get-parameter":
      return [request("get-parameter", buildGetParameterBody(hexInteger(requiredPositional(parsed, 0, "parameter sub-code"), "parameter sub-code", 0, 0xff)))];
    case "rtc-read":
      return [request("read-clock", buildReadClockBody())];
    case "user-read": {
      const address = userAddress(requiredPositional(parsed, 0, "user address"), "user address");
      const count = integerOption(parsed, "count", 1, 1, 9);
      return [request("read-user", buildReadUserBody(address, count))];
    }
    case "alias-read": {
      const address = userAddress(requiredPositional(parsed, 0, "user alias address"), "user alias address");
      const count = integerOption(parsed, "count", 1, 1, Math.min(255, maximumUserAddress - address + 1));
      return [request("read-alias", buildReadUserAliasBody(address, count))];
    }
    case "guest-read":
      return [request("read-guest", buildReadGuestAccessBody(guestAddress(requiredPositional(parsed, 0, "guest address"), "guest address")))];
    case "log-status":
      return [request("event-queue", buildEventLogQueueStatusBody())];
    case "log-read":
      return [request("event-record", buildEventLogRecordBody(eventLogIndex(requiredPositional(parsed, 0, "event log index"))))];
    case "poll":
      return [request("hosting-poll", buildHostingPollBody())];
    case "user-write":
      return [request("write-user", buildUserWriteRecord(parsed).body)];
    case "guest-write":
      return [request("write-guest", buildGuestWriteRecord(parsed).body)];
    case "user-erase": {
      const address = userAddress(requiredPositional(parsed, 0, "user address"), "user address");
      return [request("erase-user", buildEraseUserRangeBody(address, address))];
    }
    case "clock":
      return [request("set-clock", buildSetClockBody(parseDateTime(requiredPositional(parsed, 0, "controller datetime"), "datetime")))];
    case "raw": {
      const body = decodeHex(requiredPositional(parsed, 0, "complete command body"), "raw command body");
      if (body.length === 0) throw new Error("raw command body must contain a command byte");
      return [request("raw", body)];
    }
    default:
      throw new Error(`unknown command ${parsed.command}`);
  }
}

async function executeCommand(
  parsed: ParsedArguments,
  connection: CliConnectionConfig,
  requests: DirectRequest[],
  adapter: SoyalAdapter,
  transport: SoyalWire,
  now: () => Date,
): Promise<unknown> {
  const target = targetOutput(connection);
  switch (parsed.command) {
    case "status": {
      const commission = adapterData(await adapter.commission({ controller: { area: connection.area, node: connection.node } })) as unknown as JsonObject;
      const queue = decodeLogStatus(await sendBody(transport, connection, requests[3].body), connection);
      return withTarget(target, { ...commission, eventQueue: queue });
    }
    case "get-parameter":
      return withTarget(target, frameOutput(await sendBody(transport, connection, requests[0].body)));
    case "rtc-read":
      return withTarget(target, decodeClock(await sendBody(transport, connection, requests[0].body), connection, now));
    case "user-read":
      return withTarget(target, decodeUserRead(await sendBody(transport, connection, requests[0].body), connection, userAddress(requiredPositional(parsed, 0, "user address"), "user address"), integerOption(parsed, "count", 1, 1, 9)));
    case "alias-read": {
      const address = userAddress(requiredPositional(parsed, 0, "user alias address"), "user alias address");
      const count = integerOption(parsed, "count", 1, 1, Math.min(255, maximumUserAddress - address + 1));
      const result = await adapter.listUserAliases({ controller: { area: connection.area, node: connection.node }, addressStart: address, addressEnd: address + count - 1 });
      return withTarget(target, adapterData(result));
    }
    case "guest-read":
      return withTarget(target, decodeGuestRead(await sendBody(transport, connection, requests[0].body), connection, guestAddress(requiredPositional(parsed, 0, "guest address"), "guest address")));
    case "log-status":
      return withTarget(target, decodeLogStatus(await sendBody(transport, connection, requests[0].body), connection));
    case "log-read":
      return withTarget(target, decodeLogRead(await sendBody(transport, connection, requests[0].body), connection));
    case "poll":
      return withTarget(target, frameOutput(await sendBody(transport, connection, requests[0].body)));
    case "user-write": {
      const record = buildUserWriteRecord(parsed).record;
      return withTarget(target, adapterData(await adapter.writeCredential({
        controller: { area: connection.area, node: connection.node },
        address: record.userAddress,
        desired: {
          tagUid: toHex(record.tagUid),
          doorNumbers: doorsFromBitmap(record.group1, record.group2),
          accessMode: accessModeName(record.mode),
          validUntil: parsed.options.expiry,
          level: record.level,
          zone: record.zone,
          mode: "84H",
        },
      })));
    }
    case "guest-write": {
      const record = buildGuestWriteRecord(parsed).record;
      return withTarget(target, adapterData(await adapter.writeCredential({
        controller: { area: connection.area, node: connection.node },
        address: record.userAddress,
        desired: {
          tagUid: toHex(record.tagUid),
          doorNumbers: doorsFromBitmap(record.group1, record.group2),
          accessMode: guestAccessModeName(record.mode),
          validFrom: parsed.options.begin,
          validUntil: parsed.options.end,
          zone: record.zone,
        },
      })));
    }
    case "user-erase":
      return withTarget(target, adapterData(await adapter.deleteCredential({ controller: { area: connection.area, node: connection.node }, address: userAddress(requiredPositional(parsed, 0, "user address"), "user address") })));
    case "clock":
      return withTarget(target, adapterData(await adapter.syncClock({ controller: { area: connection.area, node: connection.node }, time: requiredPositional(parsed, 0, "controller datetime") })));
    case "raw":
      return withTarget(target, frameOutput(await sendBody(transport, connection, requests[0].body)));
    default:
      throw new Error(`unknown command ${parsed.command}`);
  }
}

function request(label: string, body: Uint8Array): DirectRequest {
  return { label, body };
}

function targetOutput(connection: CliConnectionConfig): JsonObject {
  return { ip: connection.ip, port: connection.port, area: connection.area, node: connection.node, did: connection.node };
}

function withTarget(target: JsonObject, value: unknown): JsonObject {
  return { target, result: value };
}

function writeAddress(parsed: ParsedArguments, requests: DirectRequest[]): string {
  if (parsed.command === "clock") return "clock";
  if (parsed.command === "raw") {
    const body = requests[0]?.body;
    if (body === undefined) return "unknown";
    if (body[0] === 0x84) return String((body[2] << 8) | body[3]);
    if (body[0] === 0x85) return String((body[1] << 8) | body[2]);
    if (body[0] === 0x8b) return String((body[2] << 16) | (body[3] << 8) | body[4]);
    return "clock";
  }
  return parsed.positionals[0] ?? "unknown";
}

function isWriteBody(body: Uint8Array): boolean {
  return body[0] === 0x84 || body[0] === 0x85 || body[0] === 0x23 || (body[0] === 0x8b && body[1] === 0x57);
}

async function sendBody(transport: SoyalWire, connection: CliConnectionConfig, body: Uint8Array): Promise<Frame> {
  const target: WireTarget = { area: connection.area, node: connection.node };
  const frame = await transport.send(target, body);
  if (frame.command === 0x05) throw new Error("controller returned 0x05 NACK");
  return frame;
}

function adapterData<T>(result: AdapterResult<T>): T {
  if (result.outcome !== CommandOutcome.OK) throw new Error(result.detail ?? result.code ?? `SOYAL operation ${result.outcome}`);
  return result.data as T;
}

function decodeUserRead(frame: Frame, connection: CliConnectionConfig, startAddress: number, count: number): JsonObject {
  const data = controllerPayload(frame.data, connection.node, count * 24, "87H user response");
  const records = Array.from({ length: count }, (_, index) => {
    const record = decodeUserRecord24(data.slice(index * 24, (index + 1) * 24));
    record.userAddress = startAddress + index;
    return userRecordOutput(record);
  });
  return { records };
}

function decodeGuestRead(frame: Frame, connection: CliConnectionConfig, address: number): JsonObject {
  const data = controllerPayload(frame.data, connection.node, [guestAccessRecordLength, 34, 35], "8BH guest response");
  const record = decodeGuestAccessRecord(data);
  record.userAddress = address;
  return { record: guestRecordOutput(record) };
}

function decodeLogStatus(frame: Frame, connection: CliConnectionConfig): JsonObject {
  const data = controllerPayload(frame.data, connection.node, 9, "25H queue status", true);
  return {
    logCounter: decode24(data, 0),
    inputPointer: decode24(data, 3),
    outputPointer: decode24(data, 6),
    extraData: data.length > 9 ? toHex(data.slice(9)) : null,
  };
}

function decodeLogRead(frame: Frame, connection: CliConnectionConfig): JsonObject {
  if (frame.command === 0x05) throw new Error("controller returned 0x05 NACK");
  const event = decodeEventRecord(frame);
  return eventOutput(event, connection);
}

function decodeClock(frame: Frame, connection: CliConnectionConfig, now: () => Date): JsonObject {
  const data = controllerPayload(frame.data, connection.node, 7, "24H clock response", true);
  const controllerTime = new Date(2000 + data[6], data[5] - 1, data[4], data[2], data[1], data[0]);
  if (Number.isNaN(controllerTime.getTime())) throw new Error("24H clock response contains an invalid date");
  const bridgeTime = now();
  return { controllerTime: controllerTime.toISOString(), bridgeTime: bridgeTime.toISOString(), clockDriftMs: controllerTime.getTime() - bridgeTime.getTime() };
}

function controllerPayload(data: Uint8Array, node: number, expectedLength: number | number[], name: string, allowTrailing = false): Uint8Array {
  const lengths = Array.isArray(expectedLength) ? expectedLength : [expectedLength];
  if (lengths.includes(data.length)) return data;
  if (data.length > 0) {
    const payloadLength = data.length - 1;
    const match = lengths.find((length) => allowTrailing ? payloadLength >= length : payloadLength === length);
    if (match !== undefined) return data.slice(1, match + 1);
  }
  throw new Error(`${name} has ${data.length} data bytes, want ${lengths.join(" or ")} with an optional source-node prefix`);
}

function userRecordOutput(record: UserRecord): JsonObject {
  return {
    address: record.userAddress,
    uid: uidString(record.tagUid) ?? null,
    doors: doorsFromBitmap(record.group1, record.group2),
    expiry: record.mode & 0x04 ? `20${String(record.year).padStart(2, "0")}-${String(record.month).padStart(2, "0")}-${String(record.day).padStart(2, "0")}` : null,
    mode: accessModeName(record.mode),
    level: record.level,
    zone: record.zone,
  };
}

function guestRecordOutput(record: GuestAccessRecord): JsonObject {
  return {
    address: record.userAddress,
    uid: uidString(record.tagUid) ?? null,
    doors: doorsFromBitmap(record.group1, record.group2),
    begin: formatRecordDate(record.beginYear, record.beginMonth, record.beginDay, record.beginHour, record.beginMinute),
    end: formatRecordDate(record.endYear, record.endMonth, record.endDay, record.endHour, record.endMinute),
    mode: accessModeName(record.mode),
    zone: record.zone,
    lift: toHex(record.lift),
  };
}

function eventOutput(event: EventRecord, connection: CliConnectionConfig): JsonObject {
  return {
    sourceNode: event.sourceNode,
    address: event.userAddress,
    uid: uidString(event.tagUid) ?? null,
    door: event.doorNumber,
    functionCode: event.functionCode,
    functionDescription: event.functionDescription,
    time: eventTime(event).toISOString(),
    area: connection.area,
    node: connection.node,
  };
}

function frameOutput(frame: Frame): JsonObject {
  return { did: frame.did, command: frame.command, commandHex: `0x${hexByte(frame.command)}`, data: toHex(frame.data), dataLength: frame.data.length };
}

function buildUserWriteRecord(parsed: ParsedArguments): { record: UserRecord; body: Uint8Array } {
  if (parsed.positionals.length < 2) throw new Error("user-write requires an address and card UID");
  const address = userAddress(parsed.positionals[0], "user address");
  const expiry = parseDateOnly(requiredOption(parsed, "expiry", "user-write requires --expiry in YYYY-MM-DD format"), "--expiry");
  const bitmap = doorBitmap(requiredOption(parsed, "doors", "user-write requires --doors"));
  const record: UserRecord = {
    userAddress: address,
    tagUid: uidBytes(parsed.positionals[1]),
    pinCode: 0,
    mode: buildMode({ accessMode: parseAccessMode(parsed.options.mode), patrol: false, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: false, enableExpireCheck: true, guest: false, passwordChangeAllowed: false }),
    zone: integerOption(parsed, "zone", 0, 0, 63),
    group1: bitmap.group1,
    group2: bitmap.group2,
    year: expiry.getFullYear() - 2000,
    month: expiry.getMonth() + 1,
    day: expiry.getDate(),
    level: integerOption(parsed, "level", 0, 0, 3),
    option: 0,
    reserved: new Uint8Array(3),
  };
  return { record, body: buildSetUserBody(record) };
}

function buildGuestWriteRecord(parsed: ParsedArguments): { record: GuestAccessRecord; body: Uint8Array } {
  if (parsed.positionals.length < 2) throw new Error("guest-write requires an address and card UID");
  const address = guestAddress(parsed.positionals[0], "guest address");
  const begin = parseDateTime(requiredOption(parsed, "begin", "guest-write requires --begin in YYYY-MM-DD HH:MM format"), "--begin");
  const end = parseDateTime(requiredOption(parsed, "end", "guest-write requires --end in YYYY-MM-DD HH:MM format"), "--end");
  if (end.getTime() <= begin.getTime()) throw new Error("--end must be after --begin");
  const bitmap = doorBitmap(requiredOption(parsed, "doors", "guest-write requires --doors"));
  const record: GuestAccessRecord = {
    userAddress: address,
    tagUid: uidBytes(parsed.positionals[1]),
    pinCode: 0,
    mode: buildGuestAccessMode({ accessMode: parseAccessMode(parsed.options.mode), patrol: false, cardOmittedAfterFingerprint: false, fingerprintOmittedAfterCard: false, enableExpireCheck: true, checkBeginAndEndTime: true, passwordChangeAllowed: false }),
    zone: integerOption(parsed, "zone", 0, 0, 63),
    group1: bitmap.group1,
    group2: bitmap.group2,
    beginYear: begin.getFullYear() - 2000,
    beginMonth: begin.getMonth() + 1,
    beginDay: begin.getDate(),
    beginHour: begin.getHours(),
    beginMinute: begin.getMinutes(),
    endYear: end.getFullYear() - 2000,
    endMonth: end.getMonth() + 1,
    endDay: end.getDate(),
    endHour: end.getHours(),
    endMinute: end.getMinutes(),
    lift: new Uint8Array(4),
  };
  return { record, body: buildSetGuestAccessBody(record) };
}

function userAddress(value: string, name: string): number {
  return integerValue(value, name, 0, maximumUserAddress);
}

function guestAddress(value: string, name: string): number {
  return integerValue(value, name, 0, maximumGuestAddress);
}

function eventLogIndex(value: string): number {
  return integerValue(value, "event log index", 0, maximumGuestAddress);
}

function integerOption(parsed: ParsedArguments, name: string, fallback: number, minimum: number, maximum: number): number {
  return parsed.options[name] === undefined ? fallback : integerValue(parsed.options[name], `--${name}`, minimum, maximum);
}

function integerValue(value: string, name: string, minimum: number, maximum: number): number {
  const trimmed = value.trim();
  const isHexadecimal = /^0x[0-9a-f]+$/i.test(trimmed);
  const isDecimal = /^[+-]?\d+$/.test(trimmed);
  const parsed = isHexadecimal ? Number.parseInt(trimmed.slice(2), 16) : Number(trimmed);
  if ((!isHexadecimal && !isDecimal) || !Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function hexInteger(value: string, name: string, minimum: number, maximum: number): number {
  const trimmed = value.trim();
  const parsed = Number.parseInt(trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed, 16);
  if (!/^(?:0x)?[0-9a-f]+$/i.test(trimmed) || !Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be a hexadecimal byte from 00 through FF`);
  }
  return parsed;
}

function requiredPositional(parsed: ParsedArguments, index: number, description: string): string {
  const value = parsed.positionals[index];
  if (value === undefined || value.trim() === "") throw new Error(`${parsed.command} requires a ${description}`);
  return value;
}

function requiredOption(parsed: ParsedArguments, name: string, message: string): string {
  const value = parsed.options[name];
  if (value === undefined || value.trim() === "") throw new Error(message);
  return value;
}

function parseAccessMode(value: string | undefined): AccessMode {
  switch (value?.trim().toLowerCase() ?? "card-only") {
    case "invalid": return AccessMode.Invalid;
    case "card-only": return AccessMode.CardOnly;
    case "card-or-pin": return AccessMode.CardOrPin;
    case "card-and-pin": return AccessMode.CardAndPin;
    default: throw new Error("--mode must be invalid, card-only, card-or-pin, or card-and-pin");
  }
}

function accessModeName(mode: number): string {
  switch ((mode >> 6) & 0x03) {
    case AccessMode.Invalid: return "invalid";
    case AccessMode.CardOnly: return "card-only";
    case AccessMode.CardOrPin: return "card-or-pin";
    case AccessMode.CardAndPin: return "card-and-pin";
    default: return "invalid";
  }
}

function guestAccessModeName(mode: number): string {
  return accessModeName(mode);
}

function doorBitmap(value: string): { group1: number; group2: number } {
  if (value.trim() === "") throw new Error("--doors must list door numbers 1 through 16");
  let bitmap = { group1: 0, group2: 0 };
  for (const part of value.split(",")) {
    if (part.trim() === "") throw new Error("--doors must list door numbers 1 through 16");
    bitmap = setDoorBitmap(bitmap.group1, bitmap.group2, integerValue(part, "door", 1, 16), true);
  }
  return bitmap;
}

function parseDateOnly(value: string, name: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value.trim())) throw new Error(`${name} must use YYYY-MM-DD`);
  return parseDateTime(`${value.trim()} 00:00`, name);
}

function parseDateTime(value: string, name: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value.trim());
  if (match === null) throw new Error(`${name} must use YYYY-MM-DD HH:MM[:SS]`);
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] ?? 0));
  if (Number.isNaN(date.getTime()) || date.getFullYear() !== Number(match[1]) || date.getMonth() !== Number(match[2]) - 1 || date.getDate() !== Number(match[3]) || date.getHours() !== Number(match[4]) || date.getMinutes() !== Number(match[5])) {
    throw new Error(`${name} contains an invalid calendar date`);
  }
  return date;
}

function formatRecordDate(year: number, month: number, day: number, hour: number, minute: number): string {
  return `20${String(year).padStart(2, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

function decodeHex(value: string, name: string): Uint8Array {
  const normalized = value.replace(/^0x/i, "").replace(/\s/g, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(normalized)) throw new Error(`${name} must be even-length hexadecimal`);
  return Uint8Array.from({ length: normalized.length / 2 }, (_, index) => Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16));
}

function toHex(value: Uint8Array): string {
  return `0x${Array.from(value, hexByte).join("")}`;
}

function hexByte(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

function decode24(data: Uint8Array, offset: number): number {
  return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
}

function writeText(writer: CliWriter, value: string): void {
  writer.write(value.endsWith("\n") ? value : `${value}\n`);
}

function writeValue(writer: CliWriter, value: unknown, compact: boolean): void {
  writeText(writer, compact ? JSON.stringify(value) : JSON.stringify(value, null, 2));
}

function writeError(writer: CliWriter, error: unknown, compact: boolean): void {
  const message = error instanceof Error ? error.message : String(error);
  writeValue(writer, compact ? { error: message } : { error: message }, compact);
}

if (import.meta.main) {
  process.exitCode = await runCli(process.argv.slice(2));
}

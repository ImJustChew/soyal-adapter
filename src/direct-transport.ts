import { AsyncLocalStorage } from "node:async_hooks";
import { buildFrame, buildFrameExtended, parseFrame, standardFrameDataLimit } from "./frame";
import type { Frame } from "./frame";
import {
  SoyalWireError,
  type SoyalWire,
  type WireTarget,
} from "./wire";

// Controllers answered in about 28 ms on-subnet during the direct probe, so a
// two-second request bound leaves room for transient LAN delay without keeping
// a failed request around for the old 701Server-sized budget.
export const defaultDirectTimeoutMs = 2_000;
// Eight held connections starved the site's own server during measurement;
// close a quiet controller socket rather than keeping it as a standing client.
export const defaultDirectIdleCloseMs = 5_000;

export interface SoyalDirectTransportOptions {
  endpoint(target: WireTarget): { host: string; port: number };
  timeoutMs?: number;
  idleCloseMs?: number;
  maxAttempts?: number;
}

interface PendingResponse {
  resolve(frame: Frame): void;
  reject(error: SoyalWireError): void;
}

interface ControllerConnection {
  readonly key: string;
  socket?: Bun.Socket<unknown>;
  connectPromise?: Promise<Bun.Socket<unknown>>;
  connectReject?: (error: SoyalWireError) => void;
  generation: number;
  buffer: Uint8Array;
  pending?: PendingResponse;
  idleTimer?: ReturnType<typeof setTimeout>;
}

interface ExclusiveLease {
  readonly key: string;
  queue: Promise<void>;
}

const standardFrameHeads = new Set([0x7e, 0x7f]);
const standardExtendedPrefix = Uint8Array.from([0xff, 0x00, 0x5a, 0xa5]);
const securityExtendedPrefix = Uint8Array.from([0xff, 0x00, 0x55, 0xaa]);

export class SoyalDirectTransport implements SoyalWire {
  public readonly timeoutMs: number;
  public readonly idleCloseMs: number;
  public readonly maxAttempts: number;

  private readonly endpoint: SoyalDirectTransportOptions["endpoint"];
  private readonly connections = new Map<string, ControllerConnection>();
  // Two simultaneous sockets to node 2 produced one valid reply and one
  // connection close before a complete frame. This queue is keyed by the
  // measured controller identity, while different node keys remain parallel.
  private readonly queues = new Map<string, Promise<void>>();
  private readonly exclusiveContext = new AsyncLocalStorage<ExclusiveLease>();
  private closed = false;

  public constructor(options: SoyalDirectTransportOptions) {
    if (typeof options.endpoint !== "function") {
      throw new SoyalWireError("SOYAL direct endpoint resolver is required", "protocol");
    }
    this.endpoint = options.endpoint;
    this.timeoutMs = validatePositiveNumber(options.timeoutMs ?? defaultDirectTimeoutMs, "timeout");
    this.idleCloseMs = validateNonNegativeNumber(options.idleCloseMs ?? defaultDirectIdleCloseMs, "idle close");
    this.maxAttempts = validatePositiveInteger(options.maxAttempts ?? 3, "maximum attempts");
  }

  public async send(target: WireTarget, body: Uint8Array, signal?: AbortSignal): Promise<Frame> {
    const key = controllerKey(target);
    const frame = buildDirectFrame(target, body);
    const lease = this.exclusiveContext.getStore();

    if (lease?.key === key) {
      return this.enqueueOnLease(lease, () => this.sendQueued(target, key, frame, signal), signal);
    }

    return this.enqueue(key, () => this.sendQueued(target, key, frame, signal), signal);
  }

  public withExclusive<ResultData>(target: WireTarget, operation: () => Promise<ResultData>): Promise<ResultData> {
    const key = controllerKey(target);
    const existingLease = this.exclusiveContext.getStore();
    if (existingLease?.key === key) return operation();

    const previous = this.queues.get(key) ?? Promise.resolve();
    const lease: ExclusiveLease = { key, queue: Promise.resolve() };
    const run = previous.then(
      () => this.runExclusiveOperation(lease, operation),
      () => this.runExclusiveOperation(lease, operation),
    );
    this.queues.set(key, run.then(() => undefined, () => undefined));
    return run;
  }

  public reset(target: WireTarget): void {
    const key = controllerKey(target);
    const connection = this.connections.get(key);
    if (connection === undefined) return;
    this.dropConnection(connection, new SoyalWireError(`SOYAL controller ${key} was reset`, "connection"));
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const closeError = new SoyalWireError("SOYAL direct transport is closed", "connection");
    for (const connection of this.connections.values()) {
      this.dropConnection(connection, closeError);
    }
    this.connections.clear();
    this.queues.clear();
  }

  private async runExclusiveOperation<ResultData>(
    lease: ExclusiveLease,
    operation: () => Promise<ResultData>,
  ): Promise<ResultData> {
    let result: ResultData;
    try {
      result = await this.exclusiveContext.run(lease, operation);
    } catch (error) {
      await lease.queue;
      throw error;
    }
    await lease.queue;
    return result;
  }

  private enqueueOnLease<ResultData>(
    lease: ExclusiveLease,
    operation: () => Promise<ResultData>,
    signal?: AbortSignal,
  ): Promise<ResultData> {
    const previous = lease.queue;
    const result = previous.then(operation, operation);
    lease.queue = result.then(() => undefined, () => undefined);
    return abortableResult(result, signal);
  }

  private enqueue<ResultData>(key: string, operation: () => Promise<ResultData>, signal?: AbortSignal): Promise<ResultData> {
    const previous = this.queues.get(key) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    this.queues.set(key, result.then(() => undefined, () => undefined));
    return abortableResult(result, signal);
  }

  private async sendQueued(
    target: WireTarget,
    key: string,
    frame: Uint8Array,
    signal: AbortSignal | undefined,
  ): Promise<Frame> {
    if (this.closed) {
      throw new SoyalWireError("SOYAL direct transport is closed", "connection");
    }
    if (signal?.aborted) {
      throw new SoyalWireError("SOYAL direct request was aborted", "aborted");
    }

    const endpoint = resolveEndpoint(this.endpoint, target);
    const connection = this.connections.get(key) ?? this.createConnection(key);
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        return await this.sendAttempt(connection, endpoint, frame, signal);
      } catch (error) {
        const wireError = asWireError(error, "connection", "SOYAL direct request failed");
        if ((wireError.code !== "timeout" && wireError.code !== "connection") || attempt === this.maxAttempts) {
          throw wireError;
        }
        // Direct controllers answer in about 28 ms on-subnet. Retries are
        // deliberately immediate; the old flat 250 ms delay existed only for
        // 701Server's owed replies, not for a fresh controller socket.
      }
    }
    throw new SoyalWireError("SOYAL direct request exhausted its attempts", "connection");
  }

  private createConnection(key: string): ControllerConnection {
    const connection: ControllerConnection = {
      key,
      generation: 0,
      buffer: new Uint8Array(0),
    };
    this.connections.set(key, connection);
    return connection;
  }

  private sendAttempt(
    connection: ControllerConnection,
    endpoint: { host: string; port: number },
    frame: Uint8Array,
    signal: AbortSignal | undefined,
  ): Promise<Frame> {
    return new Promise<Frame>((resolve, reject) => {
      let finished = false;
      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
      let abortHandler: (() => void) | undefined;

      const cleanup = (): void => {
        if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
        if (abortHandler !== undefined) signal?.removeEventListener("abort", abortHandler);
      };
      const finishResolve = (result: Frame): void => {
        if (finished) return;
        finished = true;
        cleanup();
        if (connection.pending?.resolve === finishResolve) connection.pending = undefined;
        if (connection.socket !== undefined) this.scheduleIdleClose(connection, connection.socket);
        resolve(result);
      };
      const finishReject = (error: SoyalWireError): void => {
        if (finished) return;
        finished = true;
        cleanup();
        if (connection.pending?.reject === finishReject) connection.pending = undefined;
        reject(error);
      };

      const abort = (): void => {
        const error = new SoyalWireError("SOYAL direct request was aborted", "aborted");
        this.dropConnection(connection, error);
        finishReject(error);
      };
      abortHandler = abort;
      signal?.addEventListener("abort", abortHandler, { once: true });
      timeoutHandle = setTimeout(() => {
        const error = new SoyalWireError("SOYAL direct request timed out", "timeout");
        this.dropConnection(connection, error);
        finishReject(error);
      }, this.timeoutMs);

      if (signal?.aborted) {
        abort();
        return;
      }

      this.ensureConnected(connection, endpoint).then((socket) => {
        if (finished) return;
        if (connection.socket !== socket) {
          finishReject(new SoyalWireError("SOYAL direct socket was closed before the request was written", "connection"));
          return;
        }
        if (signal?.aborted) {
          abort();
          return;
        }
        connection.pending = { resolve: finishResolve, reject: finishReject };
        try {
          socket.write(frame);
        } catch (error) {
          const wireError = new SoyalWireError(
            `SOYAL direct write failed: ${error instanceof Error ? error.message : String(error)}`,
            "connection",
          );
          this.dropConnection(connection, wireError);
          finishReject(wireError);
          return;
        }
        this.drain(connection);
      }).catch((error: unknown) => {
        const wireError = asWireError(error, "connection", "SOYAL direct connection failed");
        this.dropConnection(connection, wireError);
        finishReject(wireError);
      });
    });
  }

  private ensureConnected(
    connection: ControllerConnection,
    endpoint: { host: string; port: number },
  ): Promise<Bun.Socket<unknown>> {
    if (this.closed) return Promise.reject(new SoyalWireError("SOYAL direct transport is closed", "connection"));
    if (connection.socket !== undefined) {
      this.clearIdleTimer(connection);
      return Promise.resolve(connection.socket);
    }
    if (connection.connectPromise !== undefined) return connection.connectPromise;

    // A controller answers one client at a time. Keep exactly one live socket
    // in this state and let the per-controller queue own the only outstanding
    // request on it.
    const generation = connection.generation + 1;
    connection.generation = generation;
    let trackedConnection: Promise<Bun.Socket<unknown>>;
    const connectPromise = new Promise<Bun.Socket<unknown>>((resolve, reject) => {
      connection.connectReject = reject;
      Bun.connect({
        hostname: endpoint.host,
        port: endpoint.port,
        socket: {
          open: (socket) => {
            if (this.closed || connection.generation !== generation) {
              terminateSocket(socket);
              return;
            }
            connection.connectReject = undefined;
            connection.socket = socket;
            connection.buffer = new Uint8Array(0);
            resolve(socket);
          },
          data: (socket, chunk) => {
            if (connection.generation !== generation || connection.socket !== socket) return;
            connection.buffer = appendBytes(connection.buffer, chunk);
            this.drain(connection);
          },
          close: (socket) => {
            if (connection.generation !== generation) return;
            const error = new SoyalWireError(
              `SOYAL controller ${connection.key} closed the connection before replying`,
              "connection",
            );
            this.dropConnection(connection, error, socket);
          },
          error: (_socket, error) => {
            if (connection.generation !== generation) return;
            const wireError = new SoyalWireError(`SOYAL direct connection failed: ${error.message}`, "connection");
            this.dropConnection(connection, wireError);
          },
        },
      }).catch((error: unknown) => {
        if (connection.generation !== generation) return;
        const wireError = new SoyalWireError(
          `SOYAL direct connection failed: ${error instanceof Error ? error.message : String(error)}`,
          "connection",
        );
        connection.connectReject?.(wireError);
      });
    });

    trackedConnection = connectPromise.finally(() => {
      if (connection.connectPromise === trackedConnection) connection.connectPromise = undefined;
      if (connection.connectReject !== undefined && connection.socket === undefined) connection.connectReject = undefined;
    });
    connection.connectPromise = trackedConnection;
    return trackedConnection;
  }

  private drain(connection: ControllerConnection): void {
    const pending = connection.pending;
    if (pending === undefined) return;

    let rawFrame: Uint8Array | undefined;
    try {
      rawFrame = takeFrame(connection);
    } catch (error) {
      const protocolError = asWireError(error, "protocol", `SOYAL controller ${connection.key} sent an invalid frame`);
      this.dropConnection(connection, protocolError);
      return;
    }
    if (rawFrame === undefined) return;

    try {
      pending.resolve(parseFrame(rawFrame));
    } catch (error) {
      const protocolError = asWireError(error, "protocol", `SOYAL controller ${connection.key} sent an invalid frame`);
      this.dropConnection(connection, protocolError);
    }
  }

  private scheduleIdleClose(connection: ControllerConnection, socket: Bun.Socket<unknown>): void {
    this.clearIdleTimer(connection);
    connection.idleTimer = setTimeout(() => {
      if (connection.socket === socket && connection.pending === undefined) {
        // Eight held direct connections starved the site's own server. Close
        // every controller socket after a quiet interval, even though 701Server
        // is now gone; this one-client constraint belongs to the controller.
        this.dropConnection(
          connection,
          new SoyalWireError(`SOYAL controller ${connection.key} idle connection closed`, "connection"),
          socket,
        );
      }
    }, this.idleCloseMs);
  }

  private clearIdleTimer(connection: ControllerConnection): void {
    if (connection.idleTimer !== undefined) {
      clearTimeout(connection.idleTimer);
      connection.idleTimer = undefined;
    }
  }

  private dropConnection(
    connection: ControllerConnection,
    error: SoyalWireError,
    expectedSocket?: Bun.Socket<unknown>,
  ): void {
    const socket = connection.socket;
    if (expectedSocket !== undefined && socket !== expectedSocket) return;
    connection.socket = undefined;
    connection.generation += 1;
    connection.buffer = new Uint8Array(0);
    this.clearIdleTimer(connection);

    const pending = connection.pending;
    connection.pending = undefined;
    pending?.reject(error);

    const rejectConnection = connection.connectReject;
    connection.connectReject = undefined;
    rejectConnection?.(error);

    if (socket !== undefined) terminateSocket(socket);
  }
}

function controllerKey(target: WireTarget): string {
  return `${target.area}:${target.node}`;
}

function buildDirectFrame(target: WireTarget, body: Uint8Array): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length === 0) {
    throw new SoyalWireError("SOYAL direct request body must contain a command byte", "protocol");
  }
  if (!Number.isInteger(target.node) || target.node < 0 || target.node > 0xff) {
    throw new SoyalWireError(`SOYAL direct node must be an integer from 0 through 255`, "protocol");
  }
  if (!Number.isInteger(body[0])) {
    throw new SoyalWireError("SOYAL direct command byte is invalid", "protocol");
  }

  const command = body[0];
  const data = body.slice(1);
  try {
    // Standard frames have no area field. A non-zero area therefore always
    // selects the extended representation, even for a short command body.
    return data.length > standardFrameDataLimit || target.area !== 0
      ? buildFrameExtended(target.area, target.node, command, data)
      : buildFrame(target.node, command, data);
  } catch (error) {
    throw asWireError(error, "protocol", "SOYAL direct request frame could not be built");
  }
}

function resolveEndpoint(
  endpoint: SoyalDirectTransportOptions["endpoint"],
  target: WireTarget,
): { host: string; port: number } {
  let resolved: { host: string; port: number };
  try {
    resolved = endpoint(target);
  } catch (error) {
    throw new SoyalWireError(
      `SOYAL direct endpoint resolution failed: ${error instanceof Error ? error.message : String(error)}`,
      "connection",
    );
  }
  if (typeof resolved?.host !== "string" || resolved.host.trim().length === 0) {
    throw new SoyalWireError("SOYAL direct endpoint host must not be empty", "connection");
  }
  if (!Number.isInteger(resolved.port) || resolved.port < 0 || resolved.port > 65535) {
    throw new SoyalWireError("SOYAL direct endpoint port must be an integer from 0 through 65535", "connection");
  }
  return resolved;
}

function appendBytes(existing: Uint8Array, incoming: Uint8Array): Uint8Array {
  const combined = new Uint8Array(existing.length + incoming.length);
  combined.set(existing, 0);
  combined.set(incoming, existing.length);
  return combined;
}

function takeFrame(connection: ControllerConnection): Uint8Array | undefined {
  // TCP split and coalescing were both observed as possible stream behaviour:
  // wait for the length-declared frame and leave any following frame buffered
  // for the next serialized request. Garbage is discarded only while raising
  // a protocol error, so malformed peers cannot silently resynchronize forever.
  const buffer = connection.buffer;
  if (buffer.length === 0) return undefined;

  if (!isKnownHeadPrefix(buffer)) {
    const nextHead = findKnownHead(buffer, 1);
    const discarded = nextHead < 0 ? buffer.length : nextHead;
    connection.buffer = nextHead < 0 ? new Uint8Array(0) : buffer.slice(nextHead);
    throw new SoyalWireError(`SOYAL direct protocol discarded ${discarded} leading byte(s)`, "protocol");
  }

  if (standardFrameHeads.has(buffer[0])) {
    if (buffer.length < 2) return undefined;
    const bodyLength = buffer[1];
    if (bodyLength < 4) {
      throw new SoyalWireError(`SOYAL direct standard frame body length ${bodyLength} is too short`, "protocol");
    }
    const frameLength = 2 + bodyLength;
    if (buffer.length < frameLength) return undefined;
    connection.buffer = buffer.slice(frameLength);
    return buffer.slice(0, frameLength);
  }

  if (buffer.length < 4) return undefined;
  if (!matchesPrefix(buffer, standardExtendedPrefix) && !matchesPrefix(buffer, securityExtendedPrefix)) {
    const nextHead = findKnownHead(buffer, 1);
    const discarded = nextHead < 0 ? buffer.length : nextHead;
    connection.buffer = nextHead < 0 ? new Uint8Array(0) : buffer.slice(nextHead);
    throw new SoyalWireError(`SOYAL direct protocol discarded ${discarded} leading byte(s)`, "protocol");
  }
  if (buffer.length < 6) return undefined;
  const bodyLength = ((buffer[4] << 8) | buffer[5]) & 0x0fff;
  if (bodyLength < 4) {
    throw new SoyalWireError(`SOYAL direct extended frame body length ${bodyLength} is too short`, "protocol");
  }
  const frameLength = 6 + bodyLength;
  if (buffer.length < frameLength) return undefined;
  connection.buffer = buffer.slice(frameLength);
  return buffer.slice(0, frameLength);
}

function isKnownHeadPrefix(buffer: Uint8Array): boolean {
  if (standardFrameHeads.has(buffer[0])) return true;
  if (buffer[0] !== 0xff) return false;
  return isPrefix(buffer, standardExtendedPrefix) || isPrefix(buffer, securityExtendedPrefix);
}

function findKnownHead(buffer: Uint8Array, start: number): number {
  for (let index = start; index < buffer.length; index += 1) {
    if (standardFrameHeads.has(buffer[index])) return index;
    if (buffer[index] === 0xff && (isPrefix(buffer.subarray(index), standardExtendedPrefix) || isPrefix(buffer.subarray(index), securityExtendedPrefix))) {
      return index;
    }
  }
  return -1;
}

function isPrefix(value: Uint8Array, expected: Uint8Array): boolean {
  const comparedLength = Math.min(value.length, expected.length);
  for (let index = 0; index < comparedLength; index += 1) {
    if (value[index] !== expected[index]) return false;
  }
  return true;
}

function matchesPrefix(value: Uint8Array, expected: Uint8Array): boolean {
  return value.length >= expected.length && expected.every((byte, index) => value[index] === byte);
}

function terminateSocket(socket: Bun.Socket<unknown>): void {
  const candidate = socket as Bun.Socket<unknown> & { terminate?: () => void };
  if (typeof candidate.terminate === "function") {
    candidate.terminate();
  } else {
    socket.end();
  }
}

function asWireError(error: unknown, fallbackCode: "connection" | "protocol", prefix: string): SoyalWireError {
  if (error instanceof SoyalWireError) return error;
  return new SoyalWireError(`${prefix}: ${error instanceof Error ? error.message : String(error)}`, fallbackCode);
}

function abortableResult<ResultData>(result: Promise<ResultData>, signal?: AbortSignal): Promise<ResultData> {
  if (signal === undefined) return result;
  if (signal.aborted) return Promise.reject(new SoyalWireError("SOYAL direct request was aborted", "aborted"));

  return new Promise<ResultData>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener("abort", abort);
    const abort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new SoyalWireError("SOYAL direct request was aborted", "aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    result.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}

function validatePositiveNumber(value: number, label: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new SoyalWireError(`SOYAL direct ${label} must be greater than zero`, "protocol");
  }
  return value;
}

function validateNonNegativeNumber(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new SoyalWireError(`SOYAL direct ${label} must not be negative`, "protocol");
  }
  return value;
}

function validatePositiveInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new SoyalWireError(`SOYAL direct ${label} must be a positive integer`, "protocol");
  }
  return value;
}

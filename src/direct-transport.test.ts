import { createServer, type AddressInfo, type Server, type Socket } from "node:net";
import { describe, expect, test } from "bun:test";
import { buildFrame, buildFrameExtended, parseFrame, standardFrameDataLimit } from "./frame";
import { SoyalDirectTransport } from "./direct-transport";
import { SoyalWireError, type WireTarget } from "./wire";

type RequestHandler = (socket: Socket, request: Uint8Array, requestNumber: number) => void;

interface FakeController {
  readonly port: number;
  readonly connectionsOpened: number;
  readonly connectionsClosed: number;
  stop(): Promise<void>;
}

async function startController(handler: RequestHandler): Promise<FakeController> {
  let connectionsOpened = 0;
  let connectionsClosed = 0;
  let requestNumber = 0;
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    connectionsOpened += 1;
    sockets.add(socket);
    socket.on("error", () => undefined);
    socket.on("close", () => {
      connectionsClosed += 1;
      sockets.delete(socket);
    });

    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const frameLength = wireFrameLength(buffer);
        if (frameLength === undefined || buffer.length < frameLength) break;
        const request = new Uint8Array(buffer.subarray(0, frameLength));
        buffer = buffer.subarray(frameLength);
        handler(socket, request, requestNumber);
        requestNumber += 1;
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => resolve());
  });
  const address = server.address() as AddressInfo;

  return {
    port: address.port,
    get connectionsOpened() {
      return connectionsOpened;
    },
    get connectionsClosed() {
      return connectionsClosed;
    },
    async stop() {
      for (const socket of sockets) socket.destroy();
      if (!server.listening) return;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function wireFrameLength(buffer: Uint8Array): number | undefined {
  if (buffer.length === 0) return undefined;
  if (buffer[0] === 0x7e || buffer[0] === 0x7f) {
    if (buffer.length < 2) return undefined;
    return 2 + buffer[1];
  }
  if (buffer.length < 6) return undefined;
  if (buffer[0] !== 0xff || buffer[1] !== 0x00 || (buffer[2] !== 0x5a && buffer[2] !== 0x55)) return undefined;
  return 6 + (((buffer[4] << 8) | buffer[5]) & 0x0fff);
}

function endpoint(port: number): (target: WireTarget) => { host: string; port: number } {
  return () => ({ host: "127.0.0.1", port });
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("SoyalDirectTransport", () => {
  test("completes a clean standard-frame round trip", async () => {
    const controller = await startController((socket, request) => {
      const parsed = parseFrame(request);
      socket.write(Buffer.from(buildFrame(0, parsed.command, Uint8Array.of(0x42))));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      const result = await transport.send({ area: 0, node: 2 }, Uint8Array.of(0x24));
      expect(result).toEqual({ did: 0, command: 0x24, data: Uint8Array.of(0x42) });
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("reassembles a reply split across two TCP writes", async () => {
    const controller = await startController((socket) => {
      const reply = buildFrame(0, 0x24, Uint8Array.of(1, 2, 3));
      socket.write(Buffer.from(reply.subarray(0, 3)));
      setTimeout(() => socket.write(Buffer.from(reply.subarray(3))), 5);
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      await expect(transport.send({ area: 0, node: 2 }, Uint8Array.of(0x24))).resolves.toMatchObject({
        command: 0x24,
        data: Uint8Array.of(1, 2, 3),
      });
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("keeps two replies coalesced in one TCP write aligned", async () => {
    let requests = 0;
    const controller = await startController((socket) => {
      requests += 1;
      if (requests !== 1) return;
      const first = buildFrame(0, 0x30, Uint8Array.of(1));
      const second = buildFrame(0, 0x31, Uint8Array.of(2));
      socket.write(Buffer.from(new Uint8Array([...first, ...second])));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      const [first, second] = await Promise.all([
        transport.send({ area: 0, node: 2 }, Uint8Array.of(0x30)),
        transport.send({ area: 0, node: 2 }, Uint8Array.of(0x31)),
      ]);
      expect(first.command).toBe(0x30);
      expect(first.data).toEqual(Uint8Array.of(1));
      expect(second.command).toBe(0x31);
      expect(second.data).toEqual(Uint8Array.of(2));
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("uses extended framing for an oversized request and reply", async () => {
    const data = new Uint8Array(standardFrameDataLimit + 1).fill(0x5a);
    const controller = await startController((socket, request) => {
      expect(request[0]).toBe(0xff);
      expect(parseFrame(request).data).toEqual(data);
      socket.write(Buffer.from(buildFrameExtended(0, 0, 0x40, data)));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      const result = await transport.send({ area: 0, node: 2 }, new Uint8Array([0x40, ...data]));
      expect(result.command).toBe(0x40);
      expect(result.data).toEqual(data);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("forces extended framing when the target area is non-zero", async () => {
    const controller = await startController((socket, request) => {
      expect(request[0]).toBe(0xff);
      expect(request[4] & 0xf0).toBe(0x30);
      socket.write(Buffer.from(buildFrameExtended(3, 0, 0x41, Uint8Array.of(9))));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      const result = await transport.send({ area: 3, node: 2 }, Uint8Array.of(0x41, 9));
      expect(result).toMatchObject({ command: 0x41, data: Uint8Array.of(9) });
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("retries a timeout immediately and succeeds on the next socket", async () => {
    let requests = 0;
    const controller = await startController((socket) => {
      requests += 1;
      if (requests === 2) socket.write(Buffer.from(buildFrame(0, 0x50, Uint8Array.of(7))));
    });
    const transport = new SoyalDirectTransport({
      endpoint: endpoint(controller.port),
      timeoutMs: 30,
      idleCloseMs: 1000,
      maxAttempts: 2,
    });
    try {
      const result = await transport.send({ area: 0, node: 2 }, Uint8Array.of(0x50));
      expect(result.data).toEqual(Uint8Array.of(7));
      expect(controller.connectionsOpened).toBe(2);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("reports timeout after maxAttempts is exhausted", async () => {
    const controller = await startController(() => undefined);
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), timeoutMs: 20, maxAttempts: 2 });
    try {
      await expect(transport.send({ area: 0, node: 2 }, Uint8Array.of(0x51))).rejects.toMatchObject({
        code: "timeout",
      });
      expect(controller.connectionsOpened).toBe(2);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("aborts an in-flight request and does not retry it", async () => {
    let requests = 0;
    const controller = await startController(() => {
      requests += 1;
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), timeoutMs: 500, maxAttempts: 3 });
    const abortController = new AbortController();
    try {
      const pending = transport.send({ area: 0, node: 2 }, Uint8Array.of(0x52), abortController.signal);
      await wait(10);
      abortController.abort();
      await expect(pending).rejects.toMatchObject({ code: "aborted" });
      expect(requests).toBe(1);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("serializes overlapping sends to one controller", async () => {
    let active = 0;
    let maximumActive = 0;
    const commands: number[] = [];
    const controller = await startController((socket, request) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      const parsed = parseFrame(request);
      commands.push(parsed.command);
      setTimeout(() => {
        socket.write(Buffer.from(buildFrame(0, parsed.command, Uint8Array.of(parsed.command))));
        active -= 1;
      }, 15);
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 1000 });
    try {
      await Promise.all([
        transport.send({ area: 0, node: 2 }, Uint8Array.of(0x60)),
        transport.send({ area: 0, node: 2 }, Uint8Array.of(0x61)),
      ]);
      expect(maximumActive).toBe(1);
      expect(commands).toEqual([0x60, 0x61]);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("runs different controller nodes concurrently", async () => {
    let active = 0;
    let maximumActive = 0;
    const handler = (socket: Socket, request: Uint8Array): void => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      const parsed = parseFrame(request);
      setTimeout(() => {
        socket.write(Buffer.from(buildFrame(0, parsed.command, Uint8Array.of(parsed.command))));
        active -= 1;
      }, 20);
    };
    const node2 = await startController(handler);
    const node3 = await startController(handler);
    const transport = new SoyalDirectTransport({
      endpoint: (target) => ({ host: "127.0.0.1", port: target.node === 2 ? node2.port : node3.port }),
      idleCloseMs: 1000,
    });
    try {
      await Promise.all([
        transport.send({ area: 0, node: 2 }, Uint8Array.of(0x70)),
        transport.send({ area: 0, node: 3 }, Uint8Array.of(0x71)),
      ]);
      expect(maximumActive).toBe(2);
    } finally {
      await transport.close();
      await node2.stop();
      await node3.stop();
    }
  });

  test("closes an idle socket", async () => {
    const controller = await startController((socket) => {
      socket.write(Buffer.from(buildFrame(0, 0x80, Uint8Array.of(1))));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 20 });
    try {
      await transport.send({ area: 0, node: 2 }, Uint8Array.of(0x80));
      await wait(80);
      expect(controller.connectionsClosed).toBeGreaterThanOrEqual(1);
    } finally {
      await transport.close();
      await controller.stop();
    }
  });

  test("close drops sockets and clears the idle timer", async () => {
    const controller = await startController((socket) => {
      socket.write(Buffer.from(buildFrame(0, 0x81, Uint8Array.of(1))));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), idleCloseMs: 60_000 });
    await transport.send({ area: 0, node: 2 }, Uint8Array.of(0x81));
    await transport.close();
    await wait(20);
    expect(controller.connectionsClosed).toBeGreaterThanOrEqual(1);
    await controller.stop();
  });

  test("surfaces discarded leading stream bytes as a protocol error", async () => {
    const controller = await startController((socket) => {
      socket.write(Buffer.from([0x01, 0x02, 0x03]));
    });
    const transport = new SoyalDirectTransport({ endpoint: endpoint(controller.port), timeoutMs: 100, maxAttempts: 1 });
    try {
      await expect(transport.send({ area: 0, node: 2 }, Uint8Array.of(0x82))).rejects.toBeInstanceOf(SoyalWireError);
      await expect(transport.send({ area: 0, node: 2 }, Uint8Array.of(0x82))).rejects.toMatchObject({ code: "protocol" });
    } finally {
      await transport.close();
      await controller.stop();
    }
  });
});

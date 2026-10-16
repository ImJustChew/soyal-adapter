import { connect, type Socket } from "node:net";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { SoyalAdapter, CommandOutcome, type EventPullBody } from "./adapter";
import { buildReadClockBody } from "./command";
import { SoyalDirectTransport } from "./direct-transport";
import { buildFrame, parseFrame } from "./frame";
import { SoyalSimulator } from "./simulator";

const simulatorHost = "127.0.0.1";

interface RunningController {
  simulator: SoyalSimulator;
  transport: SoyalDirectTransport;
}

let mainController: SoyalSimulator;
let mainTransport: SoyalDirectTransport;
let mainAdapter: SoyalAdapter;

async function startController(config: ConstructorParameters<typeof SoyalSimulator>[0] = {}): Promise<SoyalSimulator> {
  return new SoyalSimulator({ host: simulatorHost, port: 0, ...config }).ready();
}

function transportFor(...controllers: SoyalSimulator[]): SoyalDirectTransport {
  return new SoyalDirectTransport({
    endpoint: (target) => {
      const controller = controllers.find((candidate) => candidate.node === target.node);
      if (controller === undefined) throw new Error(`no simulator for node ${target.node}`);
      return { host: controller.host, port: controller.port };
    },
    timeoutMs: 500,
    maxAttempts: 3,
    idleCloseMs: 1000,
  });
}

async function runningController(config: ConstructorParameters<typeof SoyalSimulator>[0] = {}): Promise<RunningController> {
  const simulator = await startController(config);
  return { simulator, transport: transportFor(simulator) };
}

function adapterFor(transport: SoyalDirectTransport, node: number, extra: ConstructorParameters<typeof SoyalAdapter>[0] = {}): SoyalAdapter {
  return new SoyalAdapter({ area: 0, node, siteId: `integration-${node}`, ...extra }, transport);
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function rawSecondConnection(port: number, frame: Uint8Array): Promise<Uint8Array> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const socket = connect({ host: simulatorHost, port });
    const finish = (): void => resolve(Buffer.concat(chunks));
    socket.once("connect", () => socket.write(Buffer.from(frame)));
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("close", finish);
    socket.once("error", finish);
    socket.setTimeout(1000, () => {
      socket.destroy();
      finish();
    });
  });
}

describe("SoyalAdapter over raw controller TCP", () => {
  beforeAll(async () => {
    mainController = await startController({ node: 2, serial: "SIM7010001", ipMac: "127.0.0.1/00:13:57:70:10:01" });
    mainTransport = transportFor(mainController);
    mainAdapter = adapterFor(mainTransport, 2);
  });

  afterAll(async () => {
    await mainTransport?.close();
    await mainController?.close();
  });

  test("writes a credential, reads it back, and keeps a stable fingerprint", async () => {
    const write = await mainAdapter.writeCredential({
      address: 42,
      desired: { tagUid: "57:B2:35", doorNumbers: [1, 16], validUntil: "2099-12-31 23:59" },
    });
    expect(write.outcome).toBe(CommandOutcome.OK);

    const firstRead = await mainAdapter.readCredential({ address: 42 });
    const secondRead = await mainAdapter.readCredential({ address: 42 });
    expect(firstRead.outcome).toBe(CommandOutcome.OK);
    expect(firstRead.data?.tagUid).toBe("000000000057B235");
    expect(firstRead.data?.doors).toEqual([1, 16]);
    expect(firstRead.data?.actualHash).toBeTruthy();
    expect(secondRead.data?.actualHash).toBe(firstRead.data?.actualHash);
  }, 15000);

  test("erases a credential and reads the address back as absent", async () => {
    const deleted = await mainAdapter.deleteCredential({ address: 42 });
    expect(deleted.outcome).toBe(CommandOutcome.OK);
    const read = await mainAdapter.readCredential({ address: 42 });
    expect(read.outcome).toBe(CommandOutcome.OK);
    expect(read.data?.tagUid).toBeNull();
  }, 15000);

  test("surfaces a refused write as rejected without retrying forever", async () => {
    const running = await runningController({ node: 6, rejectWrites: true, writeEchoCode: 5 });
    const adapter = adapterFor(running.transport, 6);
    const startedAt = Date.now();
    try {
      const result = await adapter.writeCredential({ address: 9, desired: { tagUid: "010203", doorNumbers: [1] } });
      expect(result.outcome).toBe(CommandOutcome.Rejected);
      expect(Date.now() - startedAt).toBeLessThan(1000);
    } finally {
      await running.transport.close();
      await running.simulator.close();
    }
  }, 15000);

  test("reads a wrapped event ring and reports the lost gap", async () => {
    const running = await runningController({ node: 7, logCapacity: 2 });
    const adapter = adapterFor(running.transport, 7);
    running.simulator.appendEvent({ functionCode: 11, userAddress: 1, doorNumber: 1 });
    running.simulator.appendEvent({ functionCode: 11, userAddress: 2, doorNumber: 1 });
    running.simulator.appendEvent({ functionCode: 11, userAddress: 3, doorNumber: 1 });
    try {
      const result = await adapter.pullEvents({ controller: { area: 0, node: 7 }, cursor: "0" });
      expect(result.outcome).toBe(CommandOutcome.OK);
      const data = result.data as EventPullBody;
      expect(data.events[0]?.kind).toBe("gap");
      expect(data.events[0]?.reason).toBe("log_wrapped");
      expect(data.events.filter((event) => event.kind === "event")).toHaveLength(2);
      expect(data.events.filter((event) => event.kind === "event").map((event) => event.userAddress)).toEqual([2, 3]);
    } finally {
      await running.transport.close();
      await running.simulator.close();
    }
  }, 15000);

  test("addresses two controllers alternately without a settle delay", async () => {
    const node2 = await startController({ node: 8, serial: "SIMNODE0008", ipMac: "127.0.0.8/00:13:57:70:10:08" });
    const node3 = await startController({ node: 9, serial: "SIMNODE0009", ipMac: "127.0.0.9/00:13:57:70:10:09" });
    const transport = transportFor(node2, node3);
    const adapter = adapterFor(transport, 8);
    try {
      for (let index = 0; index < 4; index += 1) {
        const first = await adapter.readCredential({ controller: { area: 0, node: 8 }, address: 20 + index });
        const second = await adapter.readCredential({ controller: { area: 0, node: 9 }, address: 20 + index });
        expect(first.outcome).toBe(CommandOutcome.OK);
        expect(second.outcome).toBe(CommandOutcome.OK);
        expect(first.data?.tagUid).toBeNull();
        expect(second.data?.tagUid).toBeNull();
      }
    } finally {
      await transport.close();
      await node2.close();
      await node3.close();
    }
  }, 15000);

  test("models the one-client limit by closing a competing connection", async () => {
    const controller = await startController({ node: 10, latencyMs: 80 });
    const firstTransport = transportFor(controller);
    const frame = buildFrame(10, 0x24, new Uint8Array());
    try {
      const first = firstTransport.send({ area: 0, node: 10 }, buildReadClockBody());
      await wait(10);
      const second = rawSecondConnection(controller.port, frame);
      const [firstFrame, secondBytes] = await Promise.all([first, second]);
      expect(firstFrame.command).toBe(0x03);
      expect(secondBytes.length).toBe(0);
    } finally {
      await firstTransport.close();
      await controller.close();
    }
  }, 15000);

  test("accepts a reply split across two TCP writes", async () => {
    const running = await runningController({ node: 11, splitReply: true });
    try {
      const frame = await running.transport.send({ area: 0, node: 11 }, buildReadClockBody());
      expect(frame.command).toBe(0x03);
      expect(frame.data[0]).toBe(11);
      expect(frame.data.length).toBe(8);
      expect(parseFrame(buildFrame(0, frame.command, frame.data))).toEqual(frame);
    } finally {
      await running.transport.close();
      await running.simulator.close();
    }
  }, 15000);
});

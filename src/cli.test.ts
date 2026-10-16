import { describe, expect, test } from "bun:test";
import { parseArguments, resolveConnection, runCli, type CliWriter } from "./cli";
import { buildFrame, parseFrame, type Frame } from "./frame";
import type { SoyalWire, WireTarget } from "./wire";

class MemoryWriter implements CliWriter {
  public value = "";

  public write(value: string): boolean {
    this.value += value;
    return true;
  }
}

class StaticWire implements SoyalWire {
  public readonly sent: Array<{ target: WireTarget; body: Uint8Array }> = [];
  public closed = false;

  public constructor(private readonly reply: Frame) {}

  public async send(target: WireTarget, body: Uint8Array): Promise<Frame> {
    this.sent.push({ target, body });
    return this.reply;
  }

  public async close(): Promise<void> {
    this.closed = true;
  }
}

function frame(command: number, data: Uint8Array = new Uint8Array()): Frame {
  return parseFrame(buildFrame(0, command, data));
}

describe("SOYAL direct CLI arguments", () => {
  test("parses --ip, --did, equals options, and flags", () => {
    const parsed = parseArguments(["user-read", "42", "--ip=192.0.2.10", "--did", "2", "--count", "2", "--json"]);
    expect(parsed.command).toBe("user-read");
    expect(parsed.positionals).toEqual(["42"]);
    expect(parsed.options).toEqual({ ip: "192.0.2.10", did: "2", count: "2" });
    expect(parsed.flags.has("json")).toBe(true);
  });

  test("requires a controller IP and does not accept the old server flags", () => {
    expect(() => resolveConnection(parseArguments(["rtc-read"]), {})).toThrow("--ip is required");
    expect(() => parseArguments(["rtc-read", "--host", "127.0.0.1"])).toThrow("unknown option --host");
    expect(() => parseArguments(["rtc-read", "--login-user", "operator"])).toThrow("unknown option --login-user");
  });

  test("resolves direct controller values and the 1621 default", () => {
    expect(resolveConnection(parseArguments(["rtc-read", "--ip", "192.0.2.10", "--node", "3"]), {})).toEqual({
      ip: "192.0.2.10",
      port: 1621,
      area: 0,
      node: 3,
      timeoutMs: 30_000,
    });
    expect(resolveConnection(parseArguments(["rtc-read"]), {
      SOYAL_IP: "192.0.2.11",
      SOYAL_CONTROLLER_PORT: "1700",
      SOYAL_AREA: "4",
      SOYAL_NODE: "5",
      SOYAL_TIMEOUT_MS: "9000",
    })).toMatchObject({ ip: "192.0.2.11", port: 1700, area: 4, node: 5, timeoutMs: 9000 });
  });
});

describe("SOYAL direct CLI requests", () => {
  test("dry-runs a complete raw command body without opening a transport", async () => {
    const output = new MemoryWriter();
    expect(await runCli(["raw", "0x12FE", "--ip", "192.0.2.10", "--node", "2", "--dry-run", "--json"], output, new MemoryWriter())).toBe(0);
    expect(JSON.parse(output.value)).toEqual({
      target: { ip: "192.0.2.10", port: 1621, area: 0, node: 2, did: 2 },
      requests: [{ label: "raw", body: "0x12FE" }],
    });
  });

  test("sends a direct 12H request and prints its parsed frame", async () => {
    const wire = new StaticWire(frame(0x03, new Uint8Array([2, 0xaa, 0xbb])));
    const output = new MemoryWriter();
    expect(await runCli(["get-parameter", "FE", "--ip", "192.0.2.10", "--node", "2", "--json"], output, new MemoryWriter(), { transport: wire })).toBe(0);
    expect(wire.sent).toHaveLength(1);
    expect(Array.from(wire.sent[0].body)).toEqual([0x12, 0xfe]);
    expect(JSON.parse(output.value).result).toMatchObject({ did: 0, command: 3, commandHex: "0x03", data: "0x02AABB" });
    expect(wire.closed).toBe(true);
  });

  test("decodes a source-node-prefixed direct 87H response", async () => {
    const data = new Uint8Array(25);
    data[0] = 2;
    data[5] = 0x57;
    data[6] = 0xb2;
    data[7] = 0x35;
    data[13] = 0x98;
    data[14] = 0xff;
    data[15] = 0xff;
    data[16] = 0xff;
    const wire = new StaticWire(frame(0x03, data));
    const output = new MemoryWriter();
    expect(await runCli(["user-read", "0", "--node", "2", "--ip", "192.0.2.10", "--json"], output, new MemoryWriter(), { transport: wire })).toBe(0);
    expect(JSON.parse(output.value).result.records[0]).toMatchObject({ address: 0, uid: "0000000057B23500", doors: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], mode: "card-or-pin" });
  });
});

describe("SOYAL direct CLI write guard", () => {
  test("requires --yes for every direct write family and does not send", async () => {
    const writeCases = [
      ["user-write", "42", "57:B2:35", "--doors", "1", "--expiry", "2027-09-08"],
      ["guest-write", "42", "57:B2:35", "--doors", "1", "--begin", "2026-08-27 09:00", "--end", "2026-08-27 17:00"],
      ["user-erase", "42"],
      ["clock", "2026-08-27 12:00"],
    ];
    for (const command of writeCases) {
      const wire = new StaticWire(frame(0x04));
      const errors = new MemoryWriter();
      expect(await runCli([...command, "--ip", "192.0.2.10", "--node", "2"], new MemoryWriter(), errors, { transport: wire })).toBe(1);
      expect(errors.value).toContain("--yes");
      expect(wire.sent).toHaveLength(0);
    }
  });

  test("prints IP, node, and address before a confirmed write", async () => {
    const wire = new StaticWire(frame(0x04));
    const errors = new MemoryWriter();
    const output = new MemoryWriter();
    expect(await runCli(["user-erase", "42", "--ip", "192.0.2.10", "--node", "2", "--yes", "--json"], output, errors, { transport: wire })).toBe(0);
    expect(errors.value).toContain("target ip=192.0.2.10 node=2 address=42");
    expect(wire.sent[0].body[0]).toBe(0x85);
  });

  test("guards a raw body that contains a write command", async () => {
    const wire = new StaticWire(frame(0x04));
    const errors = new MemoryWriter();
    expect(await runCli(["raw", "0x85002A002A", "--ip", "192.0.2.10", "--node", "2"], new MemoryWriter(), errors, { transport: wire })).toBe(1);
    expect(errors.value).toContain("--yes");
    expect(wire.sent).toHaveLength(0);
  });
});

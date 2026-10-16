import { SoyalSimulator, type SimulatorConfig } from "./simulator";

const helpText = `SOYAL raw controller simulator

Usage:
  bun run packages/soyal/src/simulator-entry.ts simulate [options]

Options:
  --host <host>              Listen host (default: 127.0.0.1)
  --port <port>              First listen port (default: 5510; one per node)
  --ports <list>             Explicit comma-separated ports, one per node
  --nodes <list>             Controller node IDs (default: 2)
  --count <n>                Number of controllers starting at node 2
  --capacity-mode <n>        User capacity: 16384, 32768, or 65535
  --reject-writes            Refuse every write with the selected echo code
  --write-echo-code <n>      Echo code for a refused write (default: 05H)
  --nack-rate <0..1>         Random write refusal rate
  --drop-rate <0..1>         Random silent reply drop rate
  --drop-replies             Silently drop every reply
  --close-mid-frame          Close after writing half of a reply
  --split-reply              Split every reply across two TCP writes
  --clock-drift <duration>   RTC offset, for example 90m
  --offline-nodes <list>     Offline node IDs, comma-separated
  --log-capacity <n>         Circular event-log capacity
  --latency <duration>       Response delay, for example 25ms
  --event-interval <duration> Synthetic access-event interval
  --seed <n>                 Deterministic fault-injection seed
  --serial <value>           Controller serial
  --ip-mac <value>           Controller IPv4/MAC identity
  --firmware <value>         Controller firmware
  --model-code <value>       Controller model code
  --dry-run                  Print the resolved simulator configuration
  -h, --help                 Show this help
`;

const valueOptions = new Set([
  "host", "port", "ports", "nodes", "count", "capacity-mode", "write-echo-code",
  "nack-rate", "drop-rate", "clock-drift", "offline-nodes", "log-capacity", "latency",
  "event-interval", "seed", "serial", "ip-mac", "firmware", "model-code",
]);
const booleanOptions = new Set(["reject-writes", "drop-replies", "close-mid-frame", "split-reply", "dry-run", "help"]);

interface ParsedArguments {
  command: string;
  values: Map<string, string>;
  flags: Set<string>;
}

function parseArguments(argumentsList: string[]): ParsedArguments {
  const parsed: ParsedArguments = { command: "", values: new Map(), flags: new Set() };
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    if (argument === "-h") {
      parsed.flags.add("help");
      continue;
    }
    if (!argument.startsWith("--")) {
      if (parsed.command.length === 0) parsed.command = argument;
      else throw new Error(`unexpected argument ${argument}`);
      continue;
    }
    const rawOption = argument.slice(2);
    const equalsIndex = rawOption.indexOf("=");
    const name = equalsIndex >= 0 ? rawOption.slice(0, equalsIndex) : rawOption;
    if (!valueOptions.has(name) && !booleanOptions.has(name)) throw new Error(`unknown option --${name}`);
    if (booleanOptions.has(name)) {
      if (equalsIndex >= 0) throw new Error(`--${name} does not accept a value`);
      parsed.flags.add(name);
      continue;
    }
    if (equalsIndex >= 0) {
      parsed.values.set(name, rawOption.slice(equalsIndex + 1));
      continue;
    }
    const nextArgument = argumentsList[index + 1];
    if (nextArgument === undefined || nextArgument.startsWith("--")) throw new Error(`--${name} requires a value`);
    index += 1;
    parsed.values.set(name, nextArgument);
  }
  if (parsed.command.length === 0) parsed.command = "simulate";
  return parsed;
}

function value(parsed: ParsedArguments, name: string): string | undefined {
  return parsed.values.get(name);
}

function integerValue(parsed: ParsedArguments, name: string, fallback?: number): number | undefined {
  const raw = value(parsed, name);
  if (raw === undefined) return fallback;
  if (!/^[+-]?\d+$/.test(raw.trim())) throw new Error(`${name} must be an integer`);
  const parsedValue = Number(raw);
  if (!Number.isSafeInteger(parsedValue)) throw new Error(`${name} must be an integer`);
  return parsedValue;
}

function numberList(parsed: ParsedArguments, name: string): number[] | undefined {
  const raw = value(parsed, name);
  if (raw === undefined) return undefined;
  const entries = raw.split(",");
  if (entries.length === 0 || entries.some((entry) => !/^[+-]?\d+$/.test(entry.trim()))) throw new Error(`${name} must contain integers`);
  return entries.map((entry) => Number(entry.trim()));
}

function rateOption(parsed: ParsedArguments, name: string): number | undefined {
  const raw = value(parsed, name);
  if (raw === undefined) return undefined;
  const parsedValue = Number(raw);
  if (!Number.isFinite(parsedValue) || parsedValue < 0 || parsedValue > 1) throw new Error(`${name} must be from 0 through 1`);
  return parsedValue;
}

function simulatorConfigs(parsed: ParsedArguments): SimulatorConfig[] {
  const nodes = numberList(parsed, "nodes") ?? (() => {
    const count = integerValue(parsed, "count", 1) ?? 1;
    if (count < 1 || count > 254) throw new Error("count must be from 1 through 254");
    return Array.from({ length: count }, (_, index) => 2 + index);
  })();
  if (nodes.length === 0 || nodes.some((node) => !Number.isInteger(node) || node < 1 || node > 254)) throw new Error("nodes must contain values from 1 through 254");
  const ports = numberList(parsed, "ports");
  if (ports !== undefined && ports.length !== nodes.length) throw new Error("ports must contain one port per node");
  const firstPort = integerValue(parsed, "port", 5510) ?? 5510;
  const common: SimulatorConfig = {
    host: value(parsed, "host"),
    capacityMode: integerValue(parsed, "capacity-mode"),
    rejectWrites: parsed.flags.has("reject-writes"),
    writeEchoCode: integerValue(parsed, "write-echo-code"),
    nackRate: rateOption(parsed, "nack-rate"),
    dropRate: rateOption(parsed, "drop-rate"),
    dropReplies: parsed.flags.has("drop-replies"),
    closeMidFrame: parsed.flags.has("close-mid-frame"),
    splitReply: parsed.flags.has("split-reply"),
    clockDrift: value(parsed, "clock-drift"),
    offlineNodes: numberList(parsed, "offline-nodes"),
    logCapacity: integerValue(parsed, "log-capacity"),
    latency: value(parsed, "latency"),
    eventInterval: value(parsed, "event-interval"),
    seed: integerValue(parsed, "seed"),
    serial: value(parsed, "serial"),
    ipMac: value(parsed, "ip-mac"),
    firmware: value(parsed, "firmware"),
    modelCode: value(parsed, "model-code"),
  };
  return nodes.map((node, index) => ({
    ...common,
    node,
    port: ports?.[index] ?? (firstPort === 0 ? 0 : firstPort + index),
    // Distinct defaults make the node-to-controller mapping visible in a
    // multi-controller run while explicit identity options remain exact.
    serial: common.serial ?? `SIM${node.toString().padStart(8, "0")}`,
    ipMac: common.ipMac ?? `127.0.0.${Math.min(node, 254)}/00:13:57:70:10:${node.toString(16).padStart(2, "0")}`,
  }));
}

function printConfiguration(simulators: SoyalSimulator[]): void {
  console.log(JSON.stringify({ simulate: simulators.map((simulator) => simulator.config) }, undefined, 2));
}

async function run(): Promise<void> {
  const parsed = parseArguments(process.argv.slice(2));
  if (parsed.flags.has("help") || parsed.command === "help") {
    console.log(helpText);
    return;
  }
  if (parsed.command !== "simulate") throw new Error(`unknown command ${parsed.command}`);
  const simulators = simulatorConfigs(parsed).map((config) => new SoyalSimulator(config));
  if (parsed.flags.has("dry-run")) {
    printConfiguration(simulators);
    return;
  }
  try {
    await Promise.all(simulators.map((simulator) => simulator.ready()));
    console.log("SOYAL raw controllers listening:");
    for (const simulator of simulators) console.log(`  node ${simulator.node} -> ${simulator.host}:${simulator.port}`);
    console.log("Press Ctrl+C to stop.");
    await new Promise<void>((resolve) => {
      const stop = (): void => {
        for (const simulator of simulators) simulator.stop();
        resolve();
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    });
  } finally {
    for (const simulator of simulators) simulator.stop();
  }
}

try {
  await run();
} catch (error) {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}

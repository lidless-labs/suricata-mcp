import * as fs from "node:fs";
import { pathToFileURL } from "node:url";
import { detectBeaconingCandidates, type BeaconCandidate } from "./analytics/beaconing.js";
import { getConfig, type SuricataConfig } from "./config.js";
import { matchesIp, matchesPartial, inTimeRange } from "./query/filters.js";
import { QueryEngine } from "./query/engine.js";
import { serveMcp } from "./mcp-server.js";
import type { AlertEvent, DnsEvent, FlowEvent } from "./types.js";

export interface CliIo {
  env?: NodeJS.ProcessEnv;
  stdout?: Pick<typeof process.stdout, "write">;
  stderr?: Pick<typeof process.stderr, "write">;
}

interface ParsedArgs {
  positional: string[];
  flags: Map<string, string | boolean>;
  json: boolean;
}

const VERSION = "2.1.0";

const HELP = `suricatactrl ${VERSION}

Usage:
  suricatactrl status [--json]
  suricatactrl alerts query [filters] [--json]
  suricatactrl flows query [filters] [--json]
  suricatactrl dns query [filters] [--json]
  suricatactrl beaconing detect [filters] [--json]
  suricatactrl mcp

Aliases:
  suricatactl      compatibility CLI alias
  suricata-mcp     MCP stdio adapter

Alert filters:
  --sid SID             --signature TEXT
  --category TEXT       --severity 1|2|3
  --src-ip IP|CIDR      --dst-ip IP|CIDR
  --src-port PORT       --dst-port PORT
  --proto TCP|UDP|ICMP  --action allowed|blocked
  --time-from ISO       --time-to ISO
  --limit N

Flow filters:
  --src-ip IP|CIDR      --dst-ip IP|CIDR
  --src-port PORT       --dst-port PORT
  --proto TCP|UDP|ICMP  --app-proto http|tls|dns
  --state STATE         --min-bytes BYTES
  --min-duration SEC    --time-from ISO
  --time-to ISO         --limit N

DNS filters:
  --query TEXT          --src-ip IP|CIDR
  --rrtype A|AAAA|TXT   --rcode NOERROR|NXDOMAIN
  --time-from ISO       --time-to ISO
  --limit N

Beaconing filters:
  --src-ip IP|CIDR      --dst-ip IP|CIDR
  --min-connections N   --jitter-threshold N
  --min-confidence N    --time-from ISO
  --time-to ISO         --limit N
`;

export async function runCli(args: string[], io: CliIo = {}): Promise<number> {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;

  try {
    const parsed = parseArgs(args);
    const [group, command] = parsed.positional;

    if (!group || group === "help" || group === "--help" || group === "-h") {
      write(stdout, HELP);
      return 0;
    }

    if (group === "version" || group === "--version" || group === "-v") {
      write(stdout, `${VERSION}\n`);
      return 0;
    }

    if (group === "mcp") {
      await serveMcp(getConfig(env));
      return 0;
    }

    if (group === "status") {
      const status = getStatus(getConfig(env));
      writeOutput(stdout, status, parsed.json, renderStatus(status));
      return 0;
    }

    const config = getConfig(env);
    const engine = new QueryEngine(config);

    if (group === "alerts" && command === "query") {
      const alerts = await queryAlerts(engine, parsed, config);
      writeOutput(stdout, alerts, parsed.json, renderAlerts(alerts));
      return 0;
    }

    if (group === "flows" && command === "query") {
      const flows = await queryFlows(engine, parsed, config);
      writeOutput(stdout, flows, parsed.json, renderFlows(flows));
      return 0;
    }

    if (group === "dns" && command === "query") {
      const records = await queryDns(engine, parsed, config);
      writeOutput(stdout, records, parsed.json, renderDns(records));
      return 0;
    }

    if (group === "beaconing" && command === "detect") {
      const result = await detectBeacons(engine, parsed, config);
      writeOutput(stdout, result, parsed.json, renderBeaconing(result.candidates));
      return 0;
    }

    write(stderr, `Unknown command: ${parsed.positional.join(" ")}\n\n${HELP}`);
    return 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    write(stderr, `suricatactrl: ${message}\n`);
    return 1;
  }
}

function parseArgs(args: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const equalIndex = arg.indexOf("=");
    if (equalIndex > -1) {
      flags.set(arg.slice(2, equalIndex), arg.slice(equalIndex + 1));
      continue;
    }

    const name = arg.slice(2);
    const next = args[i + 1];
    if (next && !next.startsWith("--")) {
      flags.set(name, next);
      i++;
    } else {
      flags.set(name, true);
    }
  }

  return {
    positional,
    flags,
    json: flags.has("json"),
  };
}

function getStatus(config: SuricataConfig) {
  return {
    ok: checkPath(config.evePath).readable,
    config: {
      evePath: config.evePath,
      eveArchiveDir: config.eveArchiveDir,
      rulesDir: config.rulesDir,
      maxResults: config.maxResults,
      unixSocket: config.unixSocket,
      zeekLogsDir: config.zeekLogsDir,
      pcapDir: config.pcapDir,
      allowMutation: config.allowMutation,
      integrations: {
        mispConfigured: Boolean(config.mispUrl && config.mispApiKey),
        thehiveConfigured: Boolean(config.thehiveUrl && config.thehiveApiKey),
      },
    },
    paths: {
      eveLog: checkPath(config.evePath),
      eveArchive: checkPath(config.eveArchiveDir),
      rulesDir: config.rulesDir ? checkPath(config.rulesDir) : null,
      zeekLogsDir: config.zeekLogsDir ? checkPath(config.zeekLogsDir) : null,
      pcapDir: config.pcapDir ? checkPath(config.pcapDir) : null,
    },
  };
}

function checkPath(target: string) {
  const status = {
    path: target,
    exists: fs.existsSync(target),
    readable: false,
  };
  if (!status.exists) return status;
  try {
    fs.accessSync(target, fs.constants.R_OK);
    status.readable = true;
  } catch {
    status.readable = false;
  }
  return status;
}

async function queryAlerts(
  engine: QueryEngine,
  parsed: ParsedArgs,
  config: SuricataConfig,
): Promise<AlertEvent[]> {
  const timeFrom = getString(parsed, "time-from");
  const timeTo = getString(parsed, "time-to");
  const sid = getNumber(parsed, "sid");
  const severity = getNumber(parsed, "severity");
  const srcPort = getNumber(parsed, "src-port");
  const dstPort = getNumber(parsed, "dst-port");

  return engine.query<AlertEvent>(
    ["alert"],
    (event) => {
      if (sid !== undefined && event.alert.signature_id !== sid) return false;
      if (getString(parsed, "signature") && !matchesPartial(event.alert.signature, getString(parsed, "signature")!)) return false;
      if (getString(parsed, "category") && !matchesPartial(event.alert.category, getString(parsed, "category")!)) return false;
      if (severity !== undefined && event.alert.severity !== severity) return false;
      if (getString(parsed, "src-ip") && !matchesIp(event.src_ip, getString(parsed, "src-ip")!)) return false;
      if (getString(parsed, "dst-ip") && !matchesIp(event.dest_ip, getString(parsed, "dst-ip")!)) return false;
      if (srcPort !== undefined && event.src_port !== srcPort) return false;
      if (dstPort !== undefined && event.dest_port !== dstPort) return false;
      if (getString(parsed, "proto") && event.proto?.toUpperCase() !== getString(parsed, "proto")!.toUpperCase()) return false;
      if (getString(parsed, "action") && event.alert.action !== getString(parsed, "action")) return false;
      if (!inTimeRange(event.timestamp, timeFrom, timeTo)) return false;
      return true;
    },
    { timeRange: { timeFrom, timeTo }, limit: getLimit(parsed, config) },
  );
}

async function queryFlows(
  engine: QueryEngine,
  parsed: ParsedArgs,
  config: SuricataConfig,
): Promise<FlowEvent[]> {
  const timeFrom = getString(parsed, "time-from");
  const timeTo = getString(parsed, "time-to");
  const srcPort = getNumber(parsed, "src-port");
  const dstPort = getNumber(parsed, "dst-port");
  const minBytes = getNumber(parsed, "min-bytes");
  const minDuration = getNumber(parsed, "min-duration");

  return engine.query<FlowEvent>(
    ["flow"],
    (event) => {
      if (getString(parsed, "src-ip") && !matchesIp(event.src_ip, getString(parsed, "src-ip")!)) return false;
      if (getString(parsed, "dst-ip") && !matchesIp(event.dest_ip, getString(parsed, "dst-ip")!)) return false;
      if (srcPort !== undefined && event.src_port !== srcPort) return false;
      if (dstPort !== undefined && event.dest_port !== dstPort) return false;
      if (getString(parsed, "proto") && event.proto?.toUpperCase() !== getString(parsed, "proto")!.toUpperCase()) return false;
      if (getString(parsed, "app-proto") && event.app_proto?.toLowerCase() !== getString(parsed, "app-proto")!.toLowerCase()) return false;
      if (getString(parsed, "state") && event.flow.state?.toLowerCase() !== getString(parsed, "state")!.toLowerCase()) return false;
      if (minBytes !== undefined && event.flow.bytes_toserver + event.flow.bytes_toclient < minBytes) return false;
      if (minDuration !== undefined && event.flow.age < minDuration) return false;
      if (!inTimeRange(event.timestamp, timeFrom, timeTo)) return false;
      return true;
    },
    { timeRange: { timeFrom, timeTo }, limit: getLimit(parsed, config) },
  );
}

async function queryDns(
  engine: QueryEngine,
  parsed: ParsedArgs,
  config: SuricataConfig,
): Promise<DnsEvent[]> {
  const timeFrom = getString(parsed, "time-from");
  const timeTo = getString(parsed, "time-to");

  return engine.query<DnsEvent>(
    ["dns"],
    (event) => {
      const query = getString(parsed, "query");
      if (query && (!event.dns.rrname || !matchesPartial(event.dns.rrname, query))) return false;
      if (getString(parsed, "src-ip") && !matchesIp(event.src_ip, getString(parsed, "src-ip")!)) return false;
      if (getString(parsed, "rrtype") && event.dns.rrtype?.toUpperCase() !== getString(parsed, "rrtype")!.toUpperCase()) return false;
      if (getString(parsed, "rcode") && event.dns.rcode?.toUpperCase() !== getString(parsed, "rcode")!.toUpperCase()) return false;
      if (!inTimeRange(event.timestamp, timeFrom, timeTo)) return false;
      return true;
    },
    { timeRange: { timeFrom, timeTo }, limit: getLimit(parsed, config) },
  );
}

async function detectBeacons(
  engine: QueryEngine,
  parsed: ParsedArgs,
  config: SuricataConfig,
): Promise<{ totalFlowsAnalyzed: number; uniquePairsAnalyzed: number; candidates: BeaconCandidate[] }> {
  const timeFrom = getString(parsed, "time-from");
  const timeTo = getString(parsed, "time-to");
  const srcIp = getString(parsed, "src-ip");
  const dstIp = getString(parsed, "dst-ip");
  const minConfidence = getNumber(parsed, "min-confidence") ?? 0;

  const flows = await engine.queryAll<FlowEvent>(
    ["flow"],
    (event) => {
      if (srcIp && !matchesIp(event.src_ip, srcIp)) return false;
      if (dstIp && !matchesIp(event.dest_ip, dstIp)) return false;
      return inTimeRange(event.timestamp, timeFrom, timeTo);
    },
    { timeRange: { timeFrom, timeTo }, maxEvents: getLimit(parsed, config) * 10 },
  );

  const result = detectBeaconingCandidates(
    flows,
    getNumber(parsed, "min-connections") ?? 10,
    getNumber(parsed, "jitter-threshold") ?? 20,
  );

  return {
    totalFlowsAnalyzed: flows.length,
    uniquePairsAnalyzed: result.uniquePairsAnalyzed,
    candidates: result.candidates.filter((candidate) => candidate.confidence >= minConfidence),
  };
}

function getString(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags.get(name);
  if (typeof value !== "string" || value.length === 0) return undefined;
  return value;
}

function getNumber(parsed: ParsedArgs, name: string): number | undefined {
  const raw = getString(parsed, name);
  if (raw === undefined) return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`--${name} must be a number`);
  }
  return value;
}

function getLimit(parsed: ParsedArgs, config: SuricataConfig): number {
  const value = getNumber(parsed, "limit") ?? 25;
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("--limit must be a positive integer");
  }
  return Math.min(value, config.maxResults);
}

function renderStatus(status: ReturnType<typeof getStatus>): string {
  const lines = [
    `status: ${status.ok ? "ok" : "needs-attention"}`,
    `eveLog: ${status.config.evePath} (${pathStatus(status.paths.eveLog)})`,
    `archive: ${status.config.eveArchiveDir} (${pathStatus(status.paths.eveArchive)})`,
    `rulesDir: ${status.config.rulesDir ?? "-"} (${status.paths.rulesDir ? pathStatus(status.paths.rulesDir) : "not-configured"})`,
    `zeekLogsDir: ${status.config.zeekLogsDir ?? "-"} (${status.paths.zeekLogsDir ? pathStatus(status.paths.zeekLogsDir) : "not-configured"})`,
    `pcapDir: ${status.config.pcapDir ?? "-"} (${status.paths.pcapDir ? pathStatus(status.paths.pcapDir) : "not-configured"})`,
    `maxResults: ${status.config.maxResults}`,
    `allowMutation: ${status.config.allowMutation}`,
    `mispConfigured: ${status.config.integrations.mispConfigured}`,
    `thehiveConfigured: ${status.config.integrations.thehiveConfigured}`,
  ];
  return `${lines.join("\n")}\n`;
}

function pathStatus(status: { exists: boolean; readable: boolean }): string {
  if (!status.exists) return "missing";
  return status.readable ? "readable" : "not-readable";
}

function renderAlerts(alerts: AlertEvent[]): string {
  if (alerts.length === 0) return "No alerts matched.\n";
  const rows = alerts.map((event) => [
    event.timestamp,
    String(event.alert.signature_id),
    String(event.alert.severity),
    String(event.src_ip ?? ""),
    `${event.dest_ip ?? ""}:${event.dest_port ?? ""}`,
    event.alert.action,
    event.alert.signature,
  ]);
  return renderTable(["time", "sid", "sev", "src", "dst", "action", "signature"], rows);
}

function renderFlows(flows: FlowEvent[]): string {
  if (flows.length === 0) return "No flows matched.\n";
  const rows = flows.map((event) => [
    event.timestamp,
    String(event.src_ip ?? ""),
    `${event.dest_ip ?? ""}:${event.dest_port ?? ""}`,
    String(event.proto ?? ""),
    String(event.app_proto ?? "-"),
    String(event.flow.state ?? "-"),
    String(event.flow.bytes_toserver + event.flow.bytes_toclient),
    `${event.flow.age}s`,
  ]);
  return renderTable(["time", "src", "dst", "proto", "app", "state", "bytes", "age"], rows);
}

function renderDns(records: DnsEvent[]): string {
  if (records.length === 0) return "No DNS records matched.\n";
  const rows = records.map((event) => [
    event.timestamp,
    String(event.src_ip ?? ""),
    String(event.dns.rrname ?? ""),
    String(event.dns.rrtype ?? "-"),
    String(event.dns.rcode ?? "-"),
    String(event.dns.rdata ?? "-"),
  ]);
  return renderTable(["time", "src", "query", "rrtype", "rcode", "rdata"], rows);
}

function renderBeaconing(candidates: BeaconCandidate[]): string {
  if (candidates.length === 0) return "No beaconing candidates matched.\n";
  const rows = candidates.map((candidate) => [
    candidate.srcIp,
    `${candidate.dstIp}:${candidate.dstPort}`,
    String(candidate.connectionCount),
    `${candidate.avgInterval}s`,
    `${candidate.jitter}%`,
    String(candidate.confidence),
  ]);
  return renderTable(["src", "dst", "count", "interval", "jitter", "confidence"], rows);
}

function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)),
  );
  const formatRow = (row: string[]) =>
    row.map((value, index) => value.padEnd(widths[index])).join("  ").trimEnd();
  return `${formatRow(headers)}\n${widths.map((width) => "-".repeat(width)).join("  ")}\n${rows.map(formatRow).join("\n")}\n`;
}

function writeOutput(
  stdout: Pick<typeof process.stdout, "write">,
  value: unknown,
  json: boolean,
  text: string,
): void {
  write(stdout, json ? `${JSON.stringify(value, null, 2)}\n` : text);
}

function write(stream: Pick<typeof process.stdout, "write">, value: string): void {
  stream.write(value);
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) {
  const code = await runCli(process.argv.slice(2));
  process.exitCode = code;
}

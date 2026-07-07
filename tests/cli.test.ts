import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");
const EVE_PATH = path.join(TEST_DATA_DIR, "eve.json");
const tempDirs: string[] = [];

function envFor(evePath = EVE_PATH, archiveDir = TEST_DATA_DIR): NodeJS.ProcessEnv {
  return {
    ...process.env,
    SURICATA_EVE_LOG: evePath,
    SURICATA_EVE_ARCHIVE: archiveDir,
    SURICATA_RULES_DIR: TEST_DATA_DIR,
    SURICATA_MAX_RESULTS: "1000",
    MISP_API_KEY: "should-not-be-printed",
    MISP_URL: "https://misp.local",
  };
}

function makeIo(env = envFor()) {
  let stdout = "";
  let stderr = "";

  return {
    io: {
      env,
      stdout: { write: (value: string) => { stdout += value; return true; } },
      stderr: { write: (value: string) => { stderr += value; return true; } },
    },
    output: () => ({ stdout, stderr }),
  };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { force: true, recursive: true });
  }
});

describe("suricatactrl CLI", () => {
  it("prints help", async () => {
    const { io, output } = makeIo();

    const code = await runCli(["help"], io);

    expect(code).toBe(0);
    expect(output().stdout).toContain("suricatactrl");
    expect(output().stdout).toContain("suricata-mcp");
  });

  it("reports status without printing secrets", async () => {
    const { io, output } = makeIo();

    const code = await runCli(["status", "--json"], io);
    const status = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(status.ok).toBe(true);
    expect(status.config.evePath).toBe(EVE_PATH);
    expect(status.config.integrations.mispConfigured).toBe(true);
    expect(output().stdout).not.toContain("should-not-be-printed");
  });

  it("queries alerts", async () => {
    const { io, output } = makeIo();

    const code = await runCli([
      "alerts",
      "query",
      "--sid",
      "2024001",
      "--json",
    ], io);
    const alerts = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts.every((event: Record<string, any>) => event.alert.signature_id === 2024001)).toBe(true);
  });

  it("queries flows", async () => {
    const { io, output } = makeIo();

    const code = await runCli([
      "flows",
      "query",
      "--app-proto",
      "http",
      "--json",
    ], io);
    const flows = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every((event: Record<string, unknown>) => event.app_proto === "http")).toBe(true);
  });

  it("queries DNS records", async () => {
    const { io, output } = makeIo();

    const code = await runCli([
      "dns",
      "query",
      "--query",
      "evil-domain",
      "--json",
    ], io);
    const records = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(records.length).toBeGreaterThan(0);
    expect(records[0].dns.rrname).toBe("evil-domain.xyz");
  });

  it("detects beaconing candidates", async () => {
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "suricatactrl-"));
    tempDirs.push(logDir);
    const evePath = path.join(logDir, "eve.json");
    const records = [];

    for (let i = 0; i < 12; i++) {
      records.push(JSON.stringify({
        timestamp: new Date(Date.UTC(2025, 0, 15, 10, i, 0)).toISOString(),
        event_type: "flow",
        src_ip: "192.168.50.10",
        src_port: 50000 + i,
        dest_ip: "203.0.113.55",
        dest_port: 443,
        proto: "TCP",
        app_proto: "tls",
        flow: {
          pkts_toserver: 4,
          pkts_toclient: 4,
          bytes_toserver: 100,
          bytes_toclient: 200,
          start: new Date(Date.UTC(2025, 0, 15, 10, i, 0)).toISOString(),
          end: new Date(Date.UTC(2025, 0, 15, 10, i, 10)).toISOString(),
          age: 10,
          state: "closed",
          reason: "timeout",
          alerted: false,
        },
      }));
    }
    fs.writeFileSync(evePath, `${records.join("\n")}\n`);

    const { io, output } = makeIo(envFor(evePath, logDir));
    const code = await runCli([
      "beaconing",
      "detect",
      "--min-connections",
      "10",
      "--json",
    ], io);
    const result = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0].srcIp).toBe("192.168.50.10");
    expect(result.candidates[0].jitter).toBe(0);
  });
});

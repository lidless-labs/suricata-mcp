import { beforeEach, describe, it, expect, vi } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";
import { checkMutationAllowed } from "../src/tools/mutation.js";
import { execFileAsync } from "../src/tools/exec.js";

vi.mock("../src/tools/exec.js", () => ({
  execFileAsync: vi.fn(),
}));

const execMock = vi.mocked(execFileAsync) as unknown as ReturnType<
  typeof vi.fn<(file: string, args: string[], opts?: unknown) => Promise<{ stdout: string; stderr: string }>>
>;

beforeEach(() => {
  // The pid file read during a rules reload must look like a pid; every other
  // call returns empty output.
  execMock.mockReset().mockImplementation(async (_file, args) => ({
    stdout: args.includes("cat") ? "4242\n" : "",
    stderr: "",
  }));
});

import { registerRuleTools } from "../src/tools/rules.js";
import { registerPcapTools } from "../src/tools/pcap.js";

const TEST_DATA_DIR = resolve(import.meta.dirname, "../test-data");

type ToolHandler = (args: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createTestConfig(overrides: Partial<SuricataConfig> = {}): SuricataConfig {
  return {
    evePath: resolve(TEST_DATA_DIR, "eve.json"),
    eveArchiveDir: TEST_DATA_DIR,
    rulesDir: TEST_DATA_DIR,
    maxResults: 1000,
    unixSocket: null,
    zeekLogsDir: null,
    pcapDir: null,
    mispUrl: null,
    mispApiKey: null,
    thehiveUrl: null,
    thehiveApiKey: null,
    allowMutation: false,
    ...overrides,
  };
}

function captureTools(server: McpServer): Map<string, ToolHandler> {
  const tools = new Map<string, ToolHandler>();
  const origTool = server.tool.bind(server);

  server.tool = ((...args: unknown[]) => {
    const name = args[0] as string;
    const handler = args[args.length - 1] as ToolHandler;
    tools.set(name, handler);
    return origTool(...(args as Parameters<typeof origTool>));
  }) as typeof server.tool;

  return tools;
}

function registerGatedTool(
  toolName: string,
  config: SuricataConfig,
): Map<string, ToolHandler> {
  const server = new McpServer({ name: "test", version: "1.0.0" });
  const tools = captureTools(server);

  if (toolName.startsWith("suricata_")) {
    registerRuleTools(server, config);
  } else if (toolName.startsWith("pcap_")) {
    registerPcapTools(server, config);
  } else {
    throw new Error(`Unknown gated tool: ${toolName}`);
  }

  return tools;
}

/** Every destructive tool that requires confirm:true plus SURICATA_ALLOW_MUTATION=1. */
const GATED_TOOLS = [
  "suricata_create_rule",
  "suricata_toggle_rule",
  "suricata_reload_rules_docker",
  "pcap_replay_suricata",
  "pcap_replay_zeek",
] as const;

type GatedToolName = (typeof GATED_TOOLS)[number];

const UNCONFIRMED_ARGS: Record<GatedToolName, Record<string, unknown>> = {
  suricata_create_rule: {
    rule: 'alert tcp any any -> any any (msg:"gate"; sid:1000100; rev:1;)',
  },
  suricata_toggle_rule: { sid: 1000100, enable: false },
  suricata_reload_rules_docker: {},
  pcap_replay_suricata: { filename: "sample.pcap" },
  pcap_replay_zeek: { filename: "sample.pcap" },
};

function confirmedArgs(toolName: GatedToolName): Record<string, unknown> {
  return { ...UNCONFIRMED_ARGS[toolName], confirm: true };
}

function expectConfirmGateError(text: string): void {
  expect(text).toContain("destructive operation");
  expect(text).toContain("confirm: true");
}

function expectMutationDisabledError(text: string): void {
  expect(text).toContain("mutating tools are disabled");
  expect(text).toContain("SURICATA_ALLOW_MUTATION");
}

describe("checkMutationAllowed", () => {
  it("refuses when mutation is disabled even with confirm:true", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: false }),
      { confirm: true },
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expect(gate.response.isError).toBe(true);
    expect(gate.response.content[0].text).toMatch(/Refusing to test action/);
    expectMutationDisabledError(gate.response.content[0].text);
  });

  it("refuses when confirm is omitted", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      {},
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expectConfirmGateError(gate.response.content[0].text);
  });

  it("refuses when confirm is false", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      { confirm: false },
      "test action",
    );
    expect(gate.allowed).toBe(false);
    if (gate.allowed) return;
    expectConfirmGateError(gate.response.content[0].text);
  });

  it("allows when mutation is enabled and confirm is true", () => {
    const gate = checkMutationAllowed(
      createTestConfig({ allowMutation: true }),
      { confirm: true },
      "test action",
    );
    expect(gate.allowed).toBe(true);
  });
});

describe("Confirmation gates on destructive tools", () => {
  describe.each(GATED_TOOLS)("%s", (toolName) => {
    it("is blocked with a clear confirm error when unconfirmed", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true })
          : createTestConfig({ allowMutation: true });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!(UNCONFIRMED_ARGS[toolName]);

      expect(result.isError).toBe(true);
      expectConfirmGateError(result.content[0].text);
    });

    it("is blocked with a clear confirm error when confirm is false", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true })
          : createTestConfig({ allowMutation: true });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!({
        ...UNCONFIRMED_ARGS[toolName],
        confirm: false,
      });

      expect(result.isError).toBe(true);
      expectConfirmGateError(result.content[0].text);
    });

    it("is blocked when mutation is disabled even with confirm:true", async () => {
      const config =
        toolName.startsWith("pcap_")
          ? createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: false })
          : createTestConfig({ allowMutation: false });

      const tools = registerGatedTool(toolName, config);
      const result = await tools.get(toolName)!(confirmedArgs(toolName));

      expect(result.isError).toBe(true);
      expectMutationDisabledError(result.content[0].text);
    });
  });

  it("suricata_create_rule proceeds past the gate and writes local.rules when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-create-gate-"));
    const localPath = join(dir, "local.rules");
    await writeFile(localPath, "");

    const rule =
      'alert tcp any any -> any any (msg:"gate-ok"; sid:1000101; rev:1;)';
    const tools = registerGatedTool(
      "suricata_create_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_create_rule")!({
      rule,
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("created");
    expect(data.sid).toBe(1000101);
    expect(await readFile(localPath, "utf-8")).toBe(rule + "\n");
  });

  it("suricata_create_rule does not write local.rules when the gate refuses", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-create-gate-refuse-"));
    const localPath = join(dir, "local.rules");
    const initial = "# placeholder\n";
    await writeFile(localPath, initial);

    const rule =
      'alert tcp any any -> any any (msg:"gate-blocked"; sid:1000102; rev:1;)';
    const tools = registerGatedTool(
      "suricata_create_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_create_rule")!({ rule });

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
    expect(await readFile(localPath, "utf-8")).toBe(initial);
  });

  it("suricata_toggle_rule proceeds past the gate when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-toggle-gate-"));
    const rule =
      'alert tcp any any -> any any (msg:"toggle-gate"; sid:1000103; rev:1;)';
    const localPath = join(dir, "local.rules");
    await writeFile(localPath, rule + "\n");

    const tools = registerGatedTool(
      "suricata_toggle_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const result = await tools.get("suricata_toggle_rule")!({
      sid: 1000103,
      enable: false,
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("updated");
    expect(data.enabled).toBe(false);
    expect(await readFile(localPath, "utf-8")).toBe("# " + rule + "\n");
  });

  it("suricata_toggle_rule does not write local.rules when the gate refuses", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-toggle-gate-refuse-"));
    const localPath = join(dir, "local.rules");
    const initial =
      'alert tcp any any -> any any (msg:"toggle-blocked"; sid:1000104; rev:1;)\n';
    await writeFile(localPath, initial);

    const tools = registerGatedTool(
      "suricata_toggle_rule",
      createTestConfig({ rulesDir: dir, allowMutation: true }),
    );

    const unconfirmed = await tools.get("suricata_toggle_rule")!({
      sid: 1000104,
      enable: false,
    });
    expect(unconfirmed.isError).toBe(true);
    expectConfirmGateError(unconfirmed.content[0].text);
    expect(await readFile(localPath, "utf-8")).toBe(initial);

    const explicitFalse = await tools.get("suricata_toggle_rule")!({
      sid: 1000104,
      enable: false,
      confirm: false,
    });
    expect(explicitFalse.isError).toBe(true);
    expect(await readFile(localPath, "utf-8")).toBe(initial);
  });

  it("suricata_toggle_rule does not write local.rules when mutation is disabled", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-toggle-disabled-"));
    const localPath = join(dir, "local.rules");
    const initial =
      'alert tcp any any -> any any (msg:"toggle-disabled"; sid:1000105; rev:1;)\n';
    await writeFile(localPath, initial);

    const tools = registerGatedTool(
      "suricata_toggle_rule",
      createTestConfig({ rulesDir: dir, allowMutation: false }),
    );

    const result = await tools.get("suricata_toggle_rule")!({
      sid: 1000105,
      enable: false,
      confirm: true,
    });
    expect(result.isError).toBe(true);
    expectMutationDisabledError(result.content[0].text);
    expect(await readFile(localPath, "utf-8")).toBe(initial);
  });

  it("suricata_reload_rules_docker proceeds past the gate when confirmed", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    expect(execMock.mock.calls.map(([file, args]) => [file, ...args])).toEqual([
      ["docker", "exec", "suricata", "suricata-update"],
      ["docker", "exec", "suricata", "cat", "/var/run/suricata.pid"],
      ["docker", "exec", "suricata", "kill", "-USR2", "4242"],
    ]);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("success");
  });

  it("suricata_reload_rules_docker never shells out when unconfirmed", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({});

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
    expect(execMock).not.toHaveBeenCalled();
  });

  it("suricata_reload_rules_docker never shells out when mutation is disabled", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: false }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({
      confirm: true,
    });

    expect(result.isError).toBe(true);
    expectMutationDisabledError(result.content[0].text);
    expect(execMock).not.toHaveBeenCalled();
  });

  it("pcap_replay_suricata proceeds past the gate when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "suricata-pcap-gate-"));
    await writeFile(join(dir, "gate-test.pcap"), "");

    const tools = registerGatedTool(
      "pcap_replay_suricata",
      createTestConfig({ pcapDir: dir, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_suricata")!({
      filename: "gate-test.pcap",
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    expect(execMock).toHaveBeenCalledTimes(1);
    expect(execMock.mock.calls[0]).toEqual([
      "docker",
      ["exec", "suricata", "suricata", "-r", "/pcaps/gate-test.pcap", "-l", "/var/log/suricata/"],
      { timeout: 120000 },
    ]);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("completed");
  });

  it("pcap_replay_zeek proceeds past the gate when confirmed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zeek-pcap-gate-"));
    await writeFile(join(dir, "gate-test.pcap"), "");

    const tools = registerGatedTool(
      "pcap_replay_zeek",
      createTestConfig({ pcapDir: dir, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_zeek")!({
      filename: "gate-test.pcap",
      confirm: true,
    });

    expect(result.isError).not.toBe(true);
    expect(execMock).toHaveBeenCalledTimes(1);
    expect(execMock.mock.calls[0]).toEqual([
      "docker",
      ["exec", "zeek", "/usr/local/zeek/bin/zeek", "-r", "/pcaps/gate-test.pcap"],
      { timeout: 120000 },
    ]);
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("completed");
  });

  it("pcap_replay_zeek is blocked when mutation is disabled", async () => {
    const tools = registerGatedTool(
      "pcap_replay_zeek",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: false }),
    );

    const result = await tools.get("pcap_replay_zeek")!({
      filename: "sample.pcap",
      confirm: true,
    });

    expect(result.isError).toBe(true);
    expectMutationDisabledError(result.content[0].text);
  });

  it("pcap_replay_suricata is blocked without confirm", async () => {
    const tools = registerGatedTool(
      "pcap_replay_suricata",
      createTestConfig({ pcapDir: TEST_DATA_DIR, allowMutation: true }),
    );

    const result = await tools.get("pcap_replay_suricata")!({
      filename: "sample.pcap",
    });

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
  });

  it("suricata_reload_rules_docker is blocked without confirm", async () => {
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({});

    expect(result.isError).toBe(true);
    expectConfirmGateError(result.content[0].text);
  });
});

describe("Command execution uses argv arrays, never a shell", () => {
  const HOSTILE_NAMES = [
    "a;touch pwned.pcap",
    "a$(id).pcap",
    "a`id`.pcap",
    "a|b.pcap",
    "a&&b.pcap",
    "a b.pcap",
    "../escape.pcap",
    "sub/dir.pcap",
  ];

  describe.each(["pcap_replay_suricata", "pcap_replay_zeek"] as const)("%s", (toolName) => {
    it.each(HOSTILE_NAMES)("rejects hostile filename %j without executing anything", async (filename) => {
      const dir = await mkdtemp(join(tmpdir(), "suricata-pcap-inject-"));
      const tools = registerGatedTool(
        toolName,
        createTestConfig({ pcapDir: dir, allowMutation: true }),
      );

      const result = await tools.get(toolName)!({ filename, confirm: true });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid filename");
      expect(execMock).not.toHaveBeenCalled();
    });

    it("passes a valid filename as exactly one argv element", async () => {
      const dir = await mkdtemp(join(tmpdir(), "suricata-pcap-argv-"));
      await writeFile(join(dir, "ok_1.2-3.pcap"), "");
      const tools = registerGatedTool(
        toolName,
        createTestConfig({ pcapDir: dir, allowMutation: true }),
      );

      const result = await tools.get(toolName)!({ filename: "ok_1.2-3.pcap", confirm: true });

      expect(result.isError).not.toBe(true);
      expect(execMock).toHaveBeenCalledTimes(1);
      const [file, args] = execMock.mock.calls[0];
      expect(file).toBe("docker");
      expect(Array.isArray(args)).toBe(true);
      expect(args.filter((a) => a.includes("ok_1.2-3.pcap"))).toEqual(["/pcaps/ok_1.2-3.pcap"]);
    });
  });

  it("suricata_reload_rules_docker refuses a pid file that is not numeric and sends no signal", async () => {
    execMock.mockReset().mockImplementation(async (_file, args) => ({
      stdout: args.includes("cat") ? "1; touch /tmp/pwned\n" : "",
      stderr: "",
    }));
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({ confirm: true });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("pid");
    expect(execMock.mock.calls.some(([, args]) => args.includes("kill"))).toBe(false);
  });

  it.each(["0", "007", "00", "12345678901", "-5"])(
    "suricata_reload_rules_docker refuses pid %j and never calls kill",
    async (badPid) => {
      execMock.mockReset().mockImplementation(async (_file, args) => ({
        stdout: args.includes("cat") ? `${badPid}\n` : "",
        stderr: "",
      }));
      const tools = registerGatedTool(
        "suricata_reload_rules_docker",
        createTestConfig({ allowMutation: true }),
      );

      const result = await tools.get("suricata_reload_rules_docker")!({ confirm: true });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("pid");
      expect(execMock.mock.calls.some(([, args]) => args.includes("kill"))).toBe(false);
    },
  );

  it("suricata_reload_rules_docker shares one 60s deadline across its steps", async () => {
    let now = 1_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    try {
      const timeouts: number[] = [];
      execMock.mockReset().mockImplementation(async (_file, args, opts) => {
        timeouts.push((opts as { timeout: number }).timeout);
        // Simulated clock: the first step (suricata-update) takes 45s.
        if (args.includes("suricata-update")) now += 45000;
        return { stdout: args.includes("cat") ? "4242\n" : "", stderr: "" };
      });
      const tools = registerGatedTool(
        "suricata_reload_rules_docker",
        createTestConfig({ allowMutation: true }),
      );

      const result = await tools.get("suricata_reload_rules_docker")!({ confirm: true });

      expect(result.isError).not.toBe(true);
      expect(timeouts).toEqual([60000, 15000, 15000]);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("suricata_reload_rules_docker refuses to start a later step once the deadline has passed", async () => {
    let now = 1_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    try {
      execMock.mockReset().mockImplementation(async (_file, args) => {
        if (args.includes("suricata-update")) now += 61000;
        return { stdout: "", stderr: "" };
      });
      const tools = registerGatedTool(
        "suricata_reload_rules_docker",
        createTestConfig({ allowMutation: true }),
      );

      const result = await tools.get("suricata_reload_rules_docker")!({ confirm: true });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("overall timeout");
      expect(execMock).toHaveBeenCalledTimes(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("suricata_reload_rules_docker stops when suricata-update fails", async () => {
    execMock.mockReset().mockRejectedValue(new Error("update failed"));
    const tools = registerGatedTool(
      "suricata_reload_rules_docker",
      createTestConfig({ allowMutation: true }),
    );

    const result = await tools.get("suricata_reload_rules_docker")!({ confirm: true });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error reloading rules");
    expect(execMock).toHaveBeenCalledTimes(1);
  });
});

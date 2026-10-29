import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { SuricataConfig } from "../config.js";
import { checkMutationAllowed } from "./mutation.js";
import { execFileAsync } from "./exec.js";

// Cap the number of replays running at once so a flood of requests can't
// exhaust host resources by spawning unbounded `docker exec` processes.
const MAX_CONCURRENT_REPLAYS = 2;
let activeReplays = 0;

/**
 * Validate a PCAP filename supplied by the caller. Only a bare filename made of
 * alphanumerics, dot, dash, and underscore is accepted. Anything else (path
 * separators, shell metacharacters, whitespace) is rejected rather than
 * silently rewritten, so a request can never replay a different file than the
 * one it named. Returns null when the name is not acceptable.
 */
function validateFilename(name: string): string | null {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;
  if (name === "." || name === "..") return null;
  return name;
}

export function registerPcapTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "pcap_list",
    externalDescription("List available PCAP files in the drop directory"),
    {},
    async () => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }
        const entries = await readdir(config.pcapDir);
        const pcaps: Array<{ name: string; size: number; modified: string }> = [];

        for (const entry of entries) {
          if (!entry.endsWith(".pcap") && !entry.endsWith(".pcapng") && !entry.endsWith(".cap")) continue;
          const fullPath = join(config.pcapDir, entry);
          const s = await stat(fullPath).catch(() => null);
          if (s && s.isFile()) {
            pcaps.push({
              name: entry,
              size: s.size,
              modified: s.mtime.toISOString(),
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: externalJson({ count: pcaps.length, pcaps }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error listing PCAPs: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "pcap_replay_suricata",
    externalDescription("Replay a PCAP file through Suricata for analysis (mutating; requires SURICATA_ALLOW_MUTATION=1 and confirm:true)"),
    {
      filename: z.string().describe("PCAP filename (must exist in PCAP directory)"),
      confirm: z.boolean().optional().describe("Must be true to run the replay (destructive opt-in)"),
    },
    async (args) => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }

        const gate = checkMutationAllowed(config, args, "replay a PCAP through Suricata");
        if (!gate.allowed) {
          return gate.response;
        }

        const safe = validateFilename(args.filename);
        if (!safe) {
          return { content: [{ type: "text" as const, text: "Invalid filename: use a bare filename containing only letters, digits, '.', '-', and '_'." }], isError: true };
        }
        // Reject names that would be parsed as a CLI option (e.g. "-r", "--help").
        if (safe.startsWith("-")) {
          return { content: [{ type: "text" as const, text: "Invalid filename: must not begin with '-'." }], isError: true };
        }

        if (activeReplays >= MAX_CONCURRENT_REPLAYS) {
          return { content: [{ type: "text" as const, text: externalText(`Too many concurrent replays (max ${MAX_CONCURRENT_REPLAYS}). Try again shortly.`) }], isError: true };
        }

        const fullPath = join(config.pcapDir, safe);
        const exists = await stat(fullPath).catch(() => null);
        if (!exists) {
          return { content: [{ type: "text" as const, text: externalText(`PCAP file not found: ${safe}`) }], isError: true };
        }

        activeReplays++;
        try {
          const { stdout, stderr } = await execFileAsync(
            "docker",
            ["exec", "suricata", "suricata", "-r", `/pcaps/${safe}`, "-l", "/var/log/suricata/"],
            { timeout: 120000 },
          );

          return {
            content: [{
              type: "text" as const,
              text: externalJson({
                status: "completed",
                filename: safe,
                stdout: stdout.trim(),
                stderr: stderr.trim(),
              }, null, 2),
            }],
          };
        } finally {
          activeReplays--;
        }
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error replaying PCAP through Suricata: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "pcap_replay_zeek",
    externalDescription("Replay a PCAP file through Zeek for analysis (mutating; requires SURICATA_ALLOW_MUTATION=1 and confirm:true)"),
    {
      filename: z.string().describe("PCAP filename (must exist in PCAP directory)"),
      confirm: z.boolean().optional().describe("Must be true to run the replay (destructive opt-in)"),
    },
    async (args) => {
      try {
        if (!config.pcapDir) {
          return { content: [{ type: "text" as const, text: "PCAP directory not configured. Set PCAP_DIR." }], isError: true };
        }

        const gate = checkMutationAllowed(config, args, "replay a PCAP through Zeek");
        if (!gate.allowed) {
          return gate.response;
        }

        const safe = validateFilename(args.filename);
        if (!safe) {
          return { content: [{ type: "text" as const, text: "Invalid filename: use a bare filename containing only letters, digits, '.', '-', and '_'." }], isError: true };
        }
        // Reject names that would be parsed as a CLI option (e.g. "-r", "--help").
        if (safe.startsWith("-")) {
          return { content: [{ type: "text" as const, text: "Invalid filename: must not begin with '-'." }], isError: true };
        }

        if (activeReplays >= MAX_CONCURRENT_REPLAYS) {
          return { content: [{ type: "text" as const, text: externalText(`Too many concurrent replays (max ${MAX_CONCURRENT_REPLAYS}). Try again shortly.`) }], isError: true };
        }

        const fullPath = join(config.pcapDir, safe);
        const exists = await stat(fullPath).catch(() => null);
        if (!exists) {
          return { content: [{ type: "text" as const, text: externalText(`PCAP file not found: ${safe}`) }], isError: true };
        }

        activeReplays++;
        try {
          const { stdout, stderr } = await execFileAsync(
            "docker",
            ["exec", "zeek", "/usr/local/zeek/bin/zeek", "-r", `/pcaps/${safe}`],
            { timeout: 120000 },
          );

          return {
            content: [{
              type: "text" as const,
              text: externalJson({
                status: "completed",
                filename: safe,
                stdout: stdout.trim(),
                stderr: stderr.trim(),
              }, null, 2),
            }],
          };
        } finally {
          activeReplays--;
        }
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error replaying PCAP through Zeek: ${error}`) }], isError: true };
      }
    },
  );
}

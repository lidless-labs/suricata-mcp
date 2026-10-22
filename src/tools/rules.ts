import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import type { SuricataConfig } from "../config.js";
import { loadAllRules } from "../parser/rules.js";
import { matchesPartial } from "../query/filters.js";
import { aggregate } from "../query/aggregation.js";
import { checkMutationAllowed } from "./mutation.js";
import { execFileAsync } from "./exec.js";

// Local rule SIDs must live in the operator-assigned range to avoid clobbering
// vendor/ET rule SIDs. 1,000,000+ is the conventional local range.
const LOCAL_SID_MIN = 1000000;

// The whole reload (suricata-update, pid read, SIGUSR2) must finish within this
// budget. Each step gets whatever time is left, not a fresh timeout.
const RELOAD_TOTAL_TIMEOUT_MS = 60000;

export function registerRuleTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "suricata_search_rules",
    "Search through Suricata rule files",
    {
      sid: z.number().optional().describe("Rule SID"),
      msg: z.string().optional().describe("Rule message (partial match)"),
      classtype: z.string().optional().describe("Rule classtype (partial match)"),
      reference: z.string().optional().describe("Rule reference (partial match)"),
      content: z.string().optional().describe("Rule content match (partial)"),
    },
    async (args) => {
      try {
        if (!config.rulesDir) {
          return {
            content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }],
            isError: true,
          };
        }

        const allRules = await loadAllRules(config.rulesDir);
        const matched = allRules.filter((rule) => {
          if (args.sid !== undefined && rule.sid !== args.sid) return false;
          if (args.msg && rule.msg && !matchesPartial(rule.msg, args.msg)) return false;
          if (args.msg && !rule.msg) return false;
          if (args.classtype && rule.classtype && !matchesPartial(rule.classtype, args.classtype)) return false;
          if (args.classtype && !rule.classtype) return false;
          if (args.reference) {
            const hasRef = rule.reference?.some((r) => matchesPartial(r, args.reference!));
            if (!hasRef) return false;
          }
          if (args.content) {
            const hasContent = rule.content?.some((c) => matchesPartial(c, args.content!));
            if (!hasContent) return false;
          }
          return true;
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ count: matched.length, rules: matched }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error searching rules: ${error}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_rule_stats",
    "Get statistics about the loaded Suricata rule set",
    {},
    async () => {
      try {
        if (!config.rulesDir) {
          return {
            content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }],
            isError: true,
          };
        }

        const allRules = await loadAllRules(config.rulesDir);
        const enabled = allRules.filter((r) => r.enabled);
        const disabled = allRules.filter((r) => !r.enabled);
        const byAction = aggregate(allRules.map((r) => r.action));
        const byClasstype = aggregate(
          allRules.filter((r) => r.classtype).map((r) => r.classtype!),
        );

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalRules: allRules.length,
              enabled: enabled.length,
              disabled: disabled.length,
              byAction,
              topClasstypes: byClasstype.slice(0, 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error getting rule stats: ${error}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_create_rule",
    "Create a custom Suricata rule and append it to local.rules (mutating; requires SURICATA_ALLOW_MUTATION=1 and confirm:true)",
    {
      rule: z.string().describe("Complete Suricata rule string (e.g., alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"...\"; sid:...; rev:1;))"),
      confirm: z.boolean().optional().describe("Must be true to write the rule (destructive opt-in)"),
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    async (args) => {
      try {
        if (!config.rulesDir) {
          return { content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }], isError: true };
        }

        const gate = checkMutationAllowed(config, args, "create a Suricata rule");
        if (!gate.allowed) {
          return gate.response;
        }

        if (/[\r\n]/.test(args.rule)) {
          return { content: [{ type: "text" as const, text: "Rule must be a single line without newline or carriage return characters." }], isError: true };
        }

        // Basic validation
        const rulePattern = /^(alert|drop|pass|reject)\s+\S+\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s*\(.+\)\s*$/;
        if (!rulePattern.test(args.rule.trim())) {
          return { content: [{ type: "text" as const, text: "Invalid rule format. Must be: action proto src srcport -> dst dstport (options;)" }], isError: true };
        }

        // Extract SID for validation
        const sidMatch = /sid\s*:\s*(\d+)/.exec(args.rule);
        if (!sidMatch) {
          return { content: [{ type: "text" as const, text: "Rule must contain a sid option." }], isError: true };
        }
        const sid = parseInt(sidMatch[1], 10);

        // Enforce the local SID range so we can't clobber vendor/ET rule SIDs.
        if (sid < LOCAL_SID_MIN) {
          return { content: [{ type: "text" as const, text: `Local rule SID must be >= ${LOCAL_SID_MIN} (got ${sid}). Lower SIDs are reserved for vendor rulesets.` }], isError: true };
        }

        // Collision check against the currently loaded ruleset.
        const existingRules = await loadAllRules(config.rulesDir);
        if (existingRules.some((r) => r.sid === sid)) {
          return { content: [{ type: "text" as const, text: `SID ${sid} already exists in the loaded ruleset. Choose a unique SID.` }], isError: true };
        }

        const localRulesPath = join(config.rulesDir, "local.rules");
        await appendFile(localRulesPath, args.rule.trim() + "\n");

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "created",
              sid,
              file: "local.rules",
              rule: args.rule.trim(),
              note: "Run suricata_reload_rules_docker to activate this rule.",
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error creating rule: ${error}` }], isError: true };
      }
    },
  );

  server.tool(
    "suricata_toggle_rule",
    "Enable or disable a Suricata rule by SID in local.rules (mutating; requires SURICATA_ALLOW_MUTATION=1 and confirm:true)",
    {
      sid: z.number().describe("Rule SID to toggle"),
      enable: z.boolean().describe("true to enable, false to disable"),
      confirm: z.boolean().optional().describe("Must be true to toggle the rule (destructive opt-in)"),
    },
    async (args) => {
      try {
        if (!config.rulesDir) {
          return { content: [{ type: "text" as const, text: "Rules directory not configured. Set SURICATA_RULES_DIR." }], isError: true };
        }

        const gate = checkMutationAllowed(config, args, "toggle a Suricata rule");
        if (!gate.allowed) {
          return gate.response;
        }

        const localRulesPath = join(config.rulesDir, "local.rules");
        let content: string;
        try {
          content = await readFile(localRulesPath, "utf-8");
        } catch {
          return { content: [{ type: "text" as const, text: "local.rules not found. Create a rule first." }], isError: true };
        }

        const lines = content.split("\n");
        let found = false;

        for (let i = 0; i < lines.length; i++) {
          const sidMatch = new RegExp(`sid\\s*:\\s*${args.sid}\\b`).exec(lines[i]);
          if (!sidMatch) continue;

          found = true;
          if (args.enable) {
            lines[i] = lines[i].replace(/^#\s*/, "");
          } else {
            if (!lines[i].startsWith("#")) {
              lines[i] = "# " + lines[i];
            }
          }
        }

        if (!found) {
          return { content: [{ type: "text" as const, text: `Rule SID ${args.sid} not found in local.rules.` }], isError: true };
        }

        await writeFile(localRulesPath, lines.join("\n"));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "updated",
              sid: args.sid,
              enabled: args.enable,
              note: "Run suricata_reload_rules_docker to apply changes.",
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error toggling rule: ${error}` }], isError: true };
      }
    },
  );

  server.tool(
    "suricata_reload_rules_docker",
    "Reload Suricata rules via Docker (suricata-update + SIGUSR2) (mutating; requires SURICATA_ALLOW_MUTATION=1 and confirm:true)",
    {
      confirm: z.boolean().optional().describe("Must be true to reload the live ruleset (destructive opt-in)"),
    },
    async (args) => {
      try {
        const gate = checkMutationAllowed(config, args, "reload the live Suricata ruleset");
        if (!gate.allowed) {
          return gate.response;
        }

        // Three argv-array steps, no shell. Each step only runs if the
        // previous one succeeded (a rejected promise jumps to the catch below).
        // The steps share one overall deadline so the total stays within
        // RELOAD_TOTAL_TIMEOUT_MS.
        const deadline = Date.now() + RELOAD_TOTAL_TIMEOUT_MS;
        const remaining = (): number => {
          const left = deadline - Date.now();
          if (left <= 0) {
            throw new Error(`reload exceeded the ${RELOAD_TOTAL_TIMEOUT_MS / 1000}s overall timeout`);
          }
          return left;
        };
        const update = await execFileAsync(
          "docker",
          ["exec", "suricata", "suricata-update"],
          { timeout: remaining() },
        );
        const pidFile = await execFileAsync(
          "docker",
          ["exec", "suricata", "cat", "/var/run/suricata.pid"],
          { timeout: remaining() },
        );
        const pid = pidFile.stdout.trim();
        // Positive, no leading zeros: "0" would signal the whole process group.
        if (!/^[1-9]\d{0,9}$/.test(pid)) {
          return { content: [{ type: "text" as const, text: "Error reloading rules: unexpected contents in /var/run/suricata.pid." }], isError: true };
        }
        const signal = await execFileAsync(
          "docker",
          ["exec", "suricata", "kill", "-USR2", pid],
          { timeout: remaining() },
        );
        const stdout = update.stdout + signal.stdout;
        const stderr = update.stderr + signal.stderr;

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "success",
              stdout: stdout.trim(),
              stderr: stderr.trim(),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error reloading rules: ${error}` }], isError: true };
      }
    },
  );
}

import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { FlowEvent } from "../types.js";
import { inTimeRange } from "../query/filters.js";
import { aggregate, topN } from "../query/aggregation.js";

const RFC1918_RANGES = [
  { start: 0x0A000000, end: 0x0AFFFFFF }, // First RFC1918 address block
  { start: 0xAC100000, end: 0xAC1FFFFF }, // Second RFC1918 address block
  { start: 0xC0A80000, end: 0xC0A8FFFF }, // Third RFC1918 address block
];

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = (result << 8) | num;
  }
  return result >>> 0;
}

export function isRfc1918(ip: string): boolean {
  const num = ipToNumber(ip);
  if (num === null) return false;
  return RFC1918_RANGES.some((r) => num >= r.start && num <= r.end);
}

// Common internal service ports that are expected
const COMMON_INTERNAL_PORTS = new Set([
  22, 53, 67, 68, 80, 88, 123, 137, 138, 139, 389, 443, 445, 464, 500, 514,
  636, 993, 995, 1900, 3389, 5353, 5355, 8080, 8443, 9090,
]);

export interface LateralCandidate {
  srcIp: string;
  uniqueInternalTargets: number;
  uniquePorts: number;
  unusualPorts: number[];
  connectionCount: number;
  targets: Array<{ ip: string; ports: number[]; count: number }>;
}

export function registerLateralMovementTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_lateral_movement_detection",
    externalDescription("Detect potential lateral movement by finding internal hosts scanning or connecting to multiple internal targets on unusual ports"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      minTargets: z.number().optional().describe("Minimum unique internal targets to flag (default 3)"),
      includeCommonPorts: z.boolean().optional().describe("Include common service ports (default false, only unusual ports)"),
      limit: z.number().optional().describe("Max results (default 20)"),
    },
    async (args) => {
      try {
        const minTargets = args.minTargets ?? 3;
        const includeCommon = args.includeCommonPorts ?? false;

        const flows = await engine.queryAll<FlowEvent>(
          ["flow"],
          (event) => {
            if (!event.src_ip || !event.dest_ip) return false;
            // Both internal
            if (!isRfc1918(event.src_ip) || !isRfc1918(event.dest_ip)) return false;
            // Not talking to self
            if (event.src_ip === event.dest_ip) return false;
            return inTimeRange(event.timestamp, args.timeFrom, args.timeTo);
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        // Group by source IP
        const srcMap = new Map<string, Map<string, Set<number>>>();
        const srcCounts = new Map<string, number>();

        for (const flow of flows) {
          const src = flow.src_ip!;
          const dst = flow.dest_ip!;
          const port = flow.dest_port ?? 0;

          if (!includeCommon && COMMON_INTERNAL_PORTS.has(port)) continue;

          let targets = srcMap.get(src);
          if (!targets) {
            targets = new Map();
            srcMap.set(src, targets);
          }

          let ports = targets.get(dst);
          if (!ports) {
            ports = new Set();
            targets.set(dst, ports);
          }
          ports.add(port);

          srcCounts.set(src, (srcCounts.get(src) ?? 0) + 1);
        }

        const candidates: LateralCandidate[] = [];

        for (const [srcIp, targets] of srcMap) {
          if (targets.size < minTargets) continue;

          const allPorts = new Set<number>();
          const targetDetails: Array<{ ip: string; ports: number[]; count: number }> = [];

          for (const [ip, ports] of targets) {
            for (const p of ports) allPorts.add(p);
            targetDetails.push({
              ip,
              ports: Array.from(ports).sort((a, b) => a - b),
              count: ports.size,
            });
          }

          const unusualPorts = Array.from(allPorts).filter((p) => !COMMON_INTERNAL_PORTS.has(p));

          candidates.push({
            srcIp,
            uniqueInternalTargets: targets.size,
            uniquePorts: allPorts.size,
            unusualPorts: unusualPorts.sort((a, b) => a - b),
            connectionCount: srcCounts.get(srcIp) ?? 0,
            targets: targetDetails.sort((a, b) => b.count - a.count).slice(0, 10),
          });
        }

        candidates.sort((a, b) => b.uniqueInternalTargets - a.uniqueInternalTargets);

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalInternalFlows: flows.length,
              lateralCandidates: candidates.length,
              minTargetsThreshold: minTargets,
              candidates: candidates.slice(0, args.limit ?? 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error detecting lateral movement: ${error}`) }], isError: true };
      }
    },
  );
}

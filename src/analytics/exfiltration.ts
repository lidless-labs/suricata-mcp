import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { FlowEvent } from "../types.js";
import { inTimeRange } from "../query/filters.js";
import { isRfc1918 } from "./lateral.js";

export interface ExfiltrationCandidate {
  srcIp: string;
  totalBytesOut: number;
  totalBytesIn: number;
  ratio: number;
  uniqueDestinations: number;
  topDestinations: Array<{ ip: string; bytesOut: number }>;
  connectionCount: number;
}

export function registerExfiltrationTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_exfiltration_detection",
    externalDescription("Detect hosts with abnormally high outbound data transfer that may indicate data exfiltration"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      minBytesOut: z.number().optional().describe("Minimum outbound bytes to flag (default 10MB = 10485760)"),
      minRatio: z.number().optional().describe("Minimum outbound/inbound byte ratio (default 3.0)"),
      limit: z.number().optional().describe("Max results (default 20)"),
    },
    async (args) => {
      try {
        const minBytes = args.minBytesOut ?? 10485760; // 10MB
        const minRatio = args.minRatio ?? 3.0;

        const flows = await engine.queryAll<FlowEvent>(
          ["flow"],
          (event) => {
            if (!event.src_ip) return false;
            // Only interested in internal->external flows
            if (!isRfc1918(event.src_ip)) return false;
            return inTimeRange(event.timestamp, args.timeFrom, args.timeTo);
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        // Aggregate by source IP
        const hostMap = new Map<string, {
          totalBytesOut: number;
          totalBytesIn: number;
          destinations: Map<string, number>;
          connCount: number;
        }>();

        for (const flow of flows) {
          const srcIp = flow.src_ip!;
          let entry = hostMap.get(srcIp);
          if (!entry) {
            entry = { totalBytesOut: 0, totalBytesIn: 0, destinations: new Map(), connCount: 0 };
            hostMap.set(srcIp, entry);
          }

          entry.totalBytesOut += flow.flow.bytes_toserver;
          entry.totalBytesIn += flow.flow.bytes_toclient;
          entry.connCount++;

          if (flow.dest_ip) {
            const existing = entry.destinations.get(flow.dest_ip) ?? 0;
            entry.destinations.set(flow.dest_ip, existing + flow.flow.bytes_toserver);
          }
        }

        const candidates: ExfiltrationCandidate[] = [];
        for (const [srcIp, data] of hostMap) {
          if (data.totalBytesOut < minBytes) continue;
          const ratio = data.totalBytesIn > 0
            ? Math.round((data.totalBytesOut / data.totalBytesIn) * 100) / 100
            : Infinity;
          if (ratio < minRatio && ratio !== Infinity) continue;

          const topDests = Array.from(data.destinations.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([ip, bytesOut]) => ({ ip, bytesOut }));

          candidates.push({
            srcIp,
            totalBytesOut: data.totalBytesOut,
            totalBytesIn: data.totalBytesIn,
            ratio,
            uniqueDestinations: data.destinations.size,
            topDestinations: topDests,
            connectionCount: data.connCount,
          });
        }

        candidates.sort((a, b) => b.totalBytesOut - a.totalBytesOut);

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalFlowsAnalyzed: flows.length,
              exfiltrationCandidates: candidates.length,
              minBytesThreshold: minBytes,
              minRatioThreshold: minRatio,
              candidates: candidates.slice(0, args.limit ?? 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error detecting exfiltration: ${error}`) }], isError: true };
      }
    },
  );
}

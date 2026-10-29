import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { AnomalyEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerAnomalyTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_anomalies",
    externalDescription("Search protocol anomalies detected by Suricata"),
    {
      type: z.string().optional().describe("Anomaly type (partial match)"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<AnomalyEvent>(
          ["anomaly"],
          (event) => {
            if (args.type && event.anomaly.type && !matchesPartial(event.anomaly.type, args.type)) return false;
            if (args.type && !event.anomaly.type) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, anomalies: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying anomalies: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

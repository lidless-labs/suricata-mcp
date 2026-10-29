import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { StatsEvent } from "../types.js";
import { inTimeRange } from "../query/filters.js";

export function registerStatsTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_engine_stats",
    externalDescription("Get Suricata engine performance statistics"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (args) => {
      try {
        const events = await engine.query<StatsEvent>(
          ["stats"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: 100 },
        );

        if (events.length === 0) {
          return {
            content: [{ type: "text" as const, text: externalJson({ message: "No stats events found" }) }],
          };
        }

        const latest = events[events.length - 1];
        const earliest = events[0];

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              statsEvents: events.length,
              timeRange: {
                from: earliest.timestamp,
                to: latest.timestamp,
              },
              latestStats: {
                uptime: latest.stats.uptime,
                capture: latest.stats.capture,
                decoder: latest.stats.decoder,
                detect: latest.stats.detect,
                flow: latest.stats.flow,
                appLayer: latest.stats.app_layer,
              },
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error getting engine stats: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

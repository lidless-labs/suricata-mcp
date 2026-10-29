import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { HttpEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerHttpTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_http",
    externalDescription("Search HTTP transaction logs from Suricata"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      hostname: z.string().optional().describe("HTTP hostname (partial match)"),
      url: z.string().optional().describe("URL path (partial match)"),
      method: z.string().optional().describe("HTTP method: GET, POST, PUT, etc."),
      statusCode: z.number().optional().describe("HTTP status code"),
      userAgent: z.string().optional().describe("User-Agent string (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<HttpEvent>(
          ["http"],
          (event) => {
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.hostname && event.http.hostname && !matchesPartial(event.http.hostname, args.hostname)) return false;
            if (args.hostname && !event.http.hostname) return false;
            if (args.url && event.http.url && !matchesPartial(event.http.url, args.url)) return false;
            if (args.url && !event.http.url) return false;
            if (args.method && event.http.http_method?.toUpperCase() !== args.method.toUpperCase()) return false;
            if (args.statusCode !== undefined && event.http.status !== args.statusCode) return false;
            if (args.userAgent && event.http.http_user_agent && !matchesPartial(event.http.http_user_agent, args.userAgent)) return false;
            if (args.userAgent && !event.http.http_user_agent) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, http: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying HTTP: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

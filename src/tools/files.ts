import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { FileinfoEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerFileTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_fileinfo",
    externalDescription("Search file extraction metadata from Suricata"),
    {
      filename: z.string().optional().describe("Filename (partial match)"),
      magic: z.string().optional().describe("File magic/type (partial match)"),
      md5: z.string().optional().describe("MD5 hash"),
      sha256: z.string().optional().describe("SHA256 hash"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      minSize: z.number().optional().describe("Minimum file size in bytes"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<FileinfoEvent>(
          ["fileinfo"],
          (event) => {
            if (args.filename && event.fileinfo.filename && !matchesPartial(event.fileinfo.filename, args.filename)) return false;
            if (args.filename && !event.fileinfo.filename) return false;
            if (args.magic && event.fileinfo.magic && !matchesPartial(event.fileinfo.magic, args.magic)) return false;
            if (args.magic && !event.fileinfo.magic) return false;
            if (args.md5 && event.fileinfo.md5 !== args.md5) return false;
            if (args.sha256 && event.fileinfo.sha256 !== args.sha256) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.minSize !== undefined && (event.fileinfo.size ?? 0) < args.minSize) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, files: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying files: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

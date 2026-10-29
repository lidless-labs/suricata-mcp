import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { SshEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerSshTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_ssh",
    externalDescription("Search SSH protocol logs from Suricata"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      clientSoftware: z.string().optional().describe("Client software version (partial match)"),
      serverSoftware: z.string().optional().describe("Server software version (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<SshEvent>(
          ["ssh"],
          (event) => {
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (args.clientSoftware && event.ssh.client?.software_version && !matchesPartial(event.ssh.client.software_version, args.clientSoftware)) return false;
            if (args.clientSoftware && !event.ssh.client?.software_version) return false;
            if (args.serverSoftware && event.ssh.server?.software_version && !matchesPartial(event.ssh.server.software_version, args.serverSoftware)) return false;
            if (args.serverSoftware && !event.ssh.server?.software_version) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, ssh: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying SSH: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { DnsEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerDnsTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_dns",
    externalDescription("Search DNS transaction logs from Suricata"),
    {
      query: z.string().optional().describe("DNS query name (partial match)"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      rrtype: z.string().optional().describe("Record type: A, AAAA, CNAME, MX, TXT, etc."),
      rcode: z.string().optional().describe("Response code: NOERROR, NXDOMAIN, SERVFAIL, etc."),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<DnsEvent>(
          ["dns"],
          (event) => {
            if (args.query && event.dns.rrname && !matchesPartial(event.dns.rrname, args.query)) return false;
            if (args.query && !event.dns.rrname) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.rrtype && event.dns.rrtype?.toUpperCase() !== args.rrtype.toUpperCase()) return false;
            if (args.rcode && event.dns.rcode?.toUpperCase() !== args.rcode.toUpperCase()) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, dns: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying DNS: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

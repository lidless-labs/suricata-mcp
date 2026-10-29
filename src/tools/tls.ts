import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { TlsEvent } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";

export function registerTlsTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_tls",
    externalDescription("Search TLS handshake logs with JA3/JA4 fingerprinting"),
    {
      sni: z.string().optional().describe("Server Name Indication (partial match)"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      version: z.string().optional().describe("TLS version"),
      ja3: z.string().optional().describe("JA3 fingerprint hash"),
      ja4: z.string().optional().describe("JA4 fingerprint"),
      subject: z.string().optional().describe("Certificate subject (partial match)"),
      issuer: z.string().optional().describe("Certificate issuer (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const events = await engine.query<TlsEvent>(
          ["tls"],
          (event) => {
            if (args.sni && event.tls.sni && !matchesPartial(event.tls.sni, args.sni)) return false;
            if (args.sni && !event.tls.sni) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (args.version && event.tls.version !== args.version) return false;
            if (args.ja3 && event.tls.ja3?.hash !== args.ja3) return false;
            if (args.ja4 && event.tls.ja4 !== args.ja4) return false;
            if (args.subject && event.tls.subject && !matchesPartial(event.tls.subject, args.subject)) return false;
            if (args.subject && !event.tls.subject) return false;
            if (args.issuer && event.tls.issuerdn && !matchesPartial(event.tls.issuerdn, args.issuer)) return false;
            if (args.issuer && !event.tls.issuerdn) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: events.length, tls: events }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying TLS: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { FlowEvent } from "../types.js";
import { matchesIp, inTimeRange } from "../query/filters.js";
import { aggregate, topN, numericStats } from "../query/aggregation.js";

export function registerFlowTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_flows",
    externalDescription("Search network flow records from Suricata"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      srcPort: z.number().optional().describe("Source port"),
      dstPort: z.number().optional().describe("Destination port"),
      proto: z.string().optional().describe("Protocol: TCP, UDP, ICMP"),
      appProto: z.string().optional().describe("Application protocol (http, tls, dns, etc.)"),
      minBytes: z.number().optional().describe("Minimum total bytes"),
      minDuration: z.number().optional().describe("Minimum flow duration in seconds"),
      state: z.string().optional().describe("Flow state: new, established, closed"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results"),
    },
    async (args) => {
      try {
        const flows = await engine.query<FlowEvent>(
          ["flow"],
          (event) => {
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (args.srcPort !== undefined && event.src_port !== args.srcPort) return false;
            if (args.dstPort !== undefined && event.dest_port !== args.dstPort) return false;
            if (args.proto && event.proto?.toUpperCase() !== args.proto.toUpperCase()) return false;
            if (args.appProto && event.app_proto?.toLowerCase() !== args.appProto.toLowerCase()) return false;
            if (args.state && event.flow.state?.toLowerCase() !== args.state.toLowerCase()) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            if (args.minBytes !== undefined) {
              const total = event.flow.bytes_toserver + event.flow.bytes_toclient;
              if (total < args.minBytes) return false;
            }
            if (args.minDuration !== undefined && event.flow.age < args.minDuration) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: flows.length, flows }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying flows: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_flow_summary",
    externalDescription("Network flow statistics with top talkers and protocol distribution"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (args) => {
      try {
        const flows = await engine.queryAll<FlowEvent>(
          ["flow"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const topSources = topN(aggregate(flows.map((f) => f.src_ip ?? "unknown")), 10);
        const topDestinations = topN(aggregate(flows.map((f) => f.dest_ip ?? "unknown")), 10);
        const protocolDist = aggregate(flows.map((f) => f.proto ?? "unknown"));
        const appProtoDist = aggregate(flows.filter((f) => f.app_proto).map((f) => f.app_proto!));

        const bytesPerFlow = flows.map((f) => f.flow.bytes_toserver + f.flow.bytes_toclient);
        const totalBytes = bytesPerFlow.reduce((a, b) => a + b, 0);
        const totalBytesToServer = flows.reduce((a, f) => a + f.flow.bytes_toserver, 0);
        const totalBytesToClient = flows.reduce((a, f) => a + f.flow.bytes_toclient, 0);

        const uniquePairs = new Set(flows.map((f) => `${f.src_ip}->${f.dest_ip}`));

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalFlows: flows.length,
              uniqueIpPairs: uniquePairs.size,
              totalBytes,
              totalBytesToServer,
              totalBytesToClient,
              byteStats: numericStats(bytesPerFlow),
              topSources,
              topDestinations,
              protocolDistribution: protocolDist,
              applicationProtocols: appProtoDist,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error generating flow summary: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

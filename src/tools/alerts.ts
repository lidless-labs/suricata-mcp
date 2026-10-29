import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { AlertEvent, Interval } from "../types.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";
import { aggregate, topN } from "../query/aggregation.js";
import { bucketEvents } from "../query/timeline.js";

export function registerAlertTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_query_alerts",
    externalDescription("Search Suricata IDS/IPS alerts with flexible filters"),
    {
      signatureId: z.number().optional().describe("Suricata rule SID"),
      signature: z.string().optional().describe("Signature message text (partial match)"),
      category: z.string().optional().describe("Alert category"),
      severity: z.union([z.literal(1), z.literal(2), z.literal(3)]).optional().describe("1=High, 2=Medium, 3=Low"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      srcPort: z.number().optional().describe("Source port"),
      dstPort: z.number().optional().describe("Destination port"),
      proto: z.string().optional().describe("Protocol: TCP, UDP, ICMP"),
      action: z.enum(["allowed", "blocked"]).optional().describe("IDS (allowed) vs IPS (blocked)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results to return"),
    },
    async (args) => {
      try {
        const alerts = await engine.query<AlertEvent>(
          ["alert"],
          (event) => {
            if (args.signatureId !== undefined && event.alert.signature_id !== args.signatureId) return false;
            if (args.signature && !matchesPartial(event.alert.signature, args.signature)) return false;
            if (args.category && !matchesPartial(event.alert.category, args.category)) return false;
            if (args.severity !== undefined && event.alert.severity !== args.severity) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (args.srcPort !== undefined && event.src_port !== args.srcPort) return false;
            if (args.dstPort !== undefined && event.dest_port !== args.dstPort) return false;
            if (args.proto && event.proto?.toUpperCase() !== args.proto.toUpperCase()) return false;
            if (args.action && event.alert.action !== args.action) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit },
        );

        return {
          content: [{ type: "text" as const, text: externalJson({ count: alerts.length, alerts }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error querying alerts: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_alert_summary",
    externalDescription("Statistical summary of alerts over a time period"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      groupBy: z.enum(["signature", "category", "severity", "src", "dst"]).optional().describe("Group results by field"),
    },
    async (args) => {
      try {
        const alerts = await engine.queryAll<AlertEvent>(
          ["alert"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const groupField = args.groupBy ?? "signature";
        const values = alerts.map((a) => {
          switch (groupField) {
            case "signature": return a.alert.signature;
            case "category": return a.alert.category;
            case "severity": return String(a.alert.severity);
            case "src": return a.src_ip ?? "unknown";
            case "dst": return a.dest_ip ?? "unknown";
          }
        });

        const grouped = aggregate(values);
        const severityDist = aggregate(alerts.map((a) => String(a.alert.severity)));
        const actionDist = aggregate(alerts.map((a) => a.alert.action));

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalAlerts: alerts.length,
              groupBy: groupField,
              groups: topN(grouped, 20),
              severityDistribution: severityDist,
              actionDistribution: actionDist,
              uniqueSources: new Set(alerts.map((a) => a.src_ip)).size,
              uniqueDestinations: new Set(alerts.map((a) => a.dest_ip)).size,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error generating alert summary: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_top_alerts",
    externalDescription("Get the most frequent and most severe alerts"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Number of top alerts to return"),
    },
    async (args) => {
      try {
        const alerts = await engine.queryAll<AlertEvent>(
          ["alert"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const sigMap = new Map<number, {
          signatureId: number;
          signature: string;
          category: string;
          severity: number;
          count: number;
          uniqueSources: Set<string>;
          uniqueDestinations: Set<string>;
          lastSeen: string;
        }>();

        for (const alert of alerts) {
          const sid = alert.alert.signature_id;
          let entry = sigMap.get(sid);
          if (!entry) {
            entry = {
              signatureId: sid,
              signature: alert.alert.signature,
              category: alert.alert.category,
              severity: alert.alert.severity,
              count: 0,
              uniqueSources: new Set(),
              uniqueDestinations: new Set(),
              lastSeen: alert.timestamp,
            };
            sigMap.set(sid, entry);
          }
          entry.count++;
          if (alert.src_ip) entry.uniqueSources.add(alert.src_ip);
          if (alert.dest_ip) entry.uniqueDestinations.add(alert.dest_ip);
          if (alert.timestamp > entry.lastSeen) entry.lastSeen = alert.timestamp;
        }

        const topByCount = Array.from(sigMap.values())
          .sort((a, b) => b.count - a.count)
          .slice(0, args.limit ?? 10)
          .map((e) => ({
            ...e,
            uniqueSources: e.uniqueSources.size,
            uniqueDestinations: e.uniqueDestinations.size,
          }));

        const topBySeverity = Array.from(sigMap.values())
          .sort((a, b) => a.severity - b.severity || b.count - a.count)
          .slice(0, args.limit ?? 10)
          .map((e) => ({
            ...e,
            uniqueSources: e.uniqueSources.size,
            uniqueDestinations: e.uniqueDestinations.size,
          }));

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalAlerts: alerts.length,
              uniqueSignatures: sigMap.size,
              topByFrequency: topByCount,
              topBySeverity,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error getting top alerts: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_alert_timeline",
    externalDescription("Get alert volume over time for spike detection"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      interval: z.enum(["1m", "5m", "15m", "1h", "1d"]).optional().describe("Time bucket interval"),
    },
    async (args) => {
      try {
        const alerts = await engine.queryAll<AlertEvent>(
          ["alert"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const interval: Interval = args.interval ?? "1h";
        const buckets = bucketEvents(alerts, interval, (a) => `severity_${a.alert.severity}`);

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalAlerts: alerts.length,
              interval,
              buckets,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error generating alert timeline: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

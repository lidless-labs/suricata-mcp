import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";
import type { QueryEngine } from "../query/engine.js";
import type { AlertEvent } from "../types.js";
import { matchesIp, inTimeRange } from "../query/filters.js";
import { parseZeekFile, findZeekLog, type ZeekRecord } from "../parser/zeek.js";

function zeekTsToIso(ts: string): string {
  const num = parseFloat(ts);
  if (isNaN(num)) return "";
  return new Date(num * 1000).toISOString();
}

function isoToEpoch(iso: string): number {
  return new Date(iso).getTime() / 1000;
}

function matchesZeekTimeWindow(
  zeekTs: string,
  alertTs: string,
  windowSeconds: number,
): boolean {
  const zeekEpoch = parseFloat(zeekTs);
  const alertEpoch = isoToEpoch(alertTs);
  if (isNaN(zeekEpoch) || isNaN(alertEpoch)) return false;
  return Math.abs(zeekEpoch - alertEpoch) <= windowSeconds;
}

function matchesIpPair(
  record: ZeekRecord,
  srcIp: string,
  dstIp: string,
): boolean {
  const zSrc = record["id.orig_h"];
  const zDst = record["id.resp_h"];
  if (!zSrc || !zDst) return false;
  return (zSrc === srcIp && zDst === dstIp) || (zSrc === dstIp && zDst === srcIp);
}

export function registerCorrelationTools(
  server: McpServer,
  engine: QueryEngine,
  config: SuricataConfig,
): void {
  server.tool(
    "correlate_alert_with_zeek",
    externalDescription("Cross-correlate a Suricata alert with Zeek logs to get enriched context (conn, dns, http, ssl data for the same IP pair and time window)"),
    {
      signatureId: z.number().optional().describe("Suricata rule SID to correlate"),
      srcIp: z.string().optional().describe("Source IP of the alert"),
      dstIp: z.string().optional().describe("Destination IP of the alert"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      windowSeconds: z.number().optional().describe("Time window around alert to search Zeek logs (default 300 = 5 minutes)"),
      limit: z.number().optional().describe("Max alerts to correlate (default 10)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }

        const window = args.windowSeconds ?? 300;

        // First, get matching Suricata alerts
        const alerts = await engine.query<AlertEvent>(
          ["alert"],
          (event) => {
            if (args.signatureId !== undefined && event.alert.signature_id !== args.signatureId) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo }, limit: args.limit ?? 10 },
        );

        if (alerts.length === 0) {
          return { content: [{ type: "text" as const, text: externalJson({ message: "No matching alerts found" }) }] };
        }

        // For each alert, find matching Zeek records
        const correlations = [];

        for (const alert of alerts) {
          const srcIp = alert.src_ip ?? "";
          const dstIp = alert.dest_ip ?? "";
          const alertTs = alert.timestamp;

          const zeekData: {
            conn: ZeekRecord[];
            dns: ZeekRecord[];
            http: ZeekRecord[];
            ssl: ZeekRecord[];
          } = { conn: [], dns: [], http: [], ssl: [] };

          const logTypes = [
            { name: "conn.log", key: "conn" as const },
            { name: "dns.log", key: "dns" as const },
            { name: "http.log", key: "http" as const },
            { name: "ssl.log", key: "ssl" as const },
          ];

          for (const logType of logTypes) {
            const logPath = await findZeekLog(config.zeekLogsDir!, logType.name);
            if (!logPath) continue;

            const { records } = await parseZeekFile(logPath, {
              maxRecords: 500,
              filter: (r) => {
                if (!r["ts"]) return false;
                if (!matchesZeekTimeWindow(r["ts"], alertTs, window)) return false;
                if (srcIp && dstIp) {
                  return matchesIpPair(r, srcIp, dstIp);
                }
                // If only one IP, match either side
                const zSrc = r["id.orig_h"] ?? "";
                const zDst = r["id.resp_h"] ?? "";
                if (srcIp) return zSrc === srcIp || zDst === srcIp;
                if (dstIp) return zSrc === dstIp || zDst === dstIp;
                return true;
              },
            });

            zeekData[logType.key] = records.slice(0, 20);
          }

          correlations.push({
            alert: {
              timestamp: alert.timestamp,
              signatureId: alert.alert.signature_id,
              signature: alert.alert.signature,
              severity: alert.alert.severity,
              category: alert.alert.category,
              srcIp: alert.src_ip,
              srcPort: alert.src_port,
              dstIp: alert.dest_ip,
              dstPort: alert.dest_port,
              proto: alert.proto,
            },
            zeek: {
              connRecords: zeekData.conn.length,
              dnsRecords: zeekData.dns.length,
              httpRecords: zeekData.http.length,
              sslRecords: zeekData.ssl.length,
              conn: zeekData.conn,
              dns: zeekData.dns,
              http: zeekData.http,
              ssl: zeekData.ssl,
            },
          });
        }

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              alertsCorrelated: correlations.length,
              windowSeconds: window,
              correlations,
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error correlating alert with Zeek: ${error}`) }], isError: true };
      }
    },
  );
}

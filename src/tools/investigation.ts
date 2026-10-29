import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type {
  AlertEvent,
  FlowEvent,
  DnsEvent,
  HttpEvent,
  TlsEvent,
  FileinfoEvent,
  SshEvent,
  AnomalyEvent,
} from "../types.js";
import { matchesIp, inTimeRange } from "../query/filters.js";
import { aggregate, topN } from "../query/aggregation.js";

export function registerInvestigationTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_investigate_host",
    externalDescription("Comprehensive investigation across all EVE event types for a specific host"),
    {
      ip: z.string().describe("IP address to investigate"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (args) => {
      try {
        const timeRange = { timeFrom: args.timeFrom, timeTo: args.timeTo };
        const ipFilter = (event: { src_ip?: string; dest_ip?: string; timestamp: string }) =>
          (matchesIp(event.src_ip, args.ip) || matchesIp(event.dest_ip, args.ip)) &&
          inTimeRange(event.timestamp, args.timeFrom, args.timeTo);

        const [alerts, flows, dns, http, tls, files, ssh, anomalies] = await Promise.all([
          engine.query<AlertEvent>(["alert"], ipFilter, { timeRange, limit: 100 }),
          engine.query<FlowEvent>(["flow"], ipFilter, { timeRange, limit: 200 }),
          engine.query<DnsEvent>(["dns"], ipFilter, { timeRange, limit: 100 }),
          engine.query<HttpEvent>(["http"], ipFilter, { timeRange, limit: 100 }),
          engine.query<TlsEvent>(["tls"], ipFilter, { timeRange, limit: 100 }),
          engine.query<FileinfoEvent>(["fileinfo"], ipFilter, { timeRange, limit: 50 }),
          engine.query<SshEvent>(["ssh"], ipFilter, { timeRange, limit: 50 }),
          engine.query<AnomalyEvent>(["anomaly"], ipFilter, { timeRange, limit: 50 }),
        ]);

        const alertSummary = alerts.length > 0
          ? {
              count: alerts.length,
              signatures: topN(aggregate(alerts.map((a) => a.alert.signature)), 10),
              severities: aggregate(alerts.map((a) => String(a.alert.severity))),
              categories: topN(aggregate(alerts.map((a) => a.alert.category)), 10),
            }
          : null;

        const flowSummary = flows.length > 0
          ? {
              count: flows.length,
              topDestinations: topN(aggregate(flows.map((f) => f.dest_ip ?? "unknown")), 10),
              topPorts: topN(aggregate(flows.map((f) => String(f.dest_port ?? 0))), 10),
              protocols: aggregate(flows.map((f) => f.app_proto ?? f.proto ?? "unknown")),
              totalBytesOut: flows.reduce((a, f) => a + f.flow.bytes_toserver, 0),
              totalBytesIn: flows.reduce((a, f) => a + f.flow.bytes_toclient, 0),
            }
          : null;

        const dnsSummary = dns.length > 0
          ? {
              count: dns.length,
              topQueries: topN(aggregate(dns.filter((d) => d.dns.rrname).map((d) => d.dns.rrname!)), 10),
              queryTypes: aggregate(dns.filter((d) => d.dns.rrtype).map((d) => d.dns.rrtype!)),
            }
          : null;

        const httpSummary = http.length > 0
          ? {
              count: http.length,
              topHosts: topN(aggregate(http.filter((h) => h.http.hostname).map((h) => h.http.hostname!)), 10),
              methods: aggregate(http.filter((h) => h.http.http_method).map((h) => h.http.http_method!)),
              userAgents: topN(aggregate(http.filter((h) => h.http.http_user_agent).map((h) => h.http.http_user_agent!)), 5),
            }
          : null;

        const tlsSummary = tls.length > 0
          ? {
              count: tls.length,
              topSnis: topN(aggregate(tls.filter((t) => t.tls.sni).map((t) => t.tls.sni!)), 10),
              versions: aggregate(tls.filter((t) => t.tls.version).map((t) => t.tls.version!)),
              ja3Hashes: topN(aggregate(tls.filter((t) => t.tls.ja3?.hash).map((t) => t.tls.ja3!.hash!)), 5),
            }
          : null;

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              ip: args.ip,
              alerts: alertSummary,
              flows: flowSummary,
              dns: dnsSummary,
              http: httpSummary,
              tls: tlsSummary,
              files: files.length > 0 ? { count: files.length, files } : null,
              ssh: ssh.length > 0 ? { count: ssh.length, connections: ssh } : null,
              anomalies: anomalies.length > 0 ? { count: anomalies.length, anomalies } : null,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error investigating host: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_investigate_alert",
    externalDescription("Deep investigation of a specific alert, correlating with flow and protocol data"),
    {
      signatureId: z.number().describe("Suricata rule SID"),
      srcIp: z.string().optional().describe("Source IP to filter by"),
      dstIp: z.string().optional().describe("Destination IP to filter by"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (args) => {
      try {
        const timeRange = { timeFrom: args.timeFrom, timeTo: args.timeTo };

        const alerts = await engine.query<AlertEvent>(
          ["alert"],
          (event) => {
            if (event.alert.signature_id !== args.signatureId) return false;
            if (args.srcIp && !matchesIp(event.src_ip, args.srcIp)) return false;
            if (args.dstIp && !matchesIp(event.dest_ip, args.dstIp)) return false;
            if (!inTimeRange(event.timestamp, args.timeFrom, args.timeTo)) return false;
            return true;
          },
          { timeRange, limit: 100 },
        );

        if (alerts.length === 0) {
          return {
            content: [{ type: "text" as const, text: externalJson({ message: "No alerts found for this signature" }) }],
          };
        }

        const ipPairs = new Set(alerts.map((a) => `${a.src_ip}:${a.dest_ip}`));
        const relatedFlows: FlowEvent[] = [];
        const relatedHttp: HttpEvent[] = [];
        const relatedDns: DnsEvent[] = [];
        const relatedTls: TlsEvent[] = [];

        for (const pair of ipPairs) {
          const [srcIp, dstIp] = pair.split(":");
          const pairFilter = (event: { src_ip?: string; dest_ip?: string; timestamp: string }) =>
            event.src_ip === srcIp &&
            event.dest_ip === dstIp &&
            inTimeRange(event.timestamp, args.timeFrom, args.timeTo);

          const [flows, http, dns, tls] = await Promise.all([
            engine.query<FlowEvent>(["flow"], pairFilter, { timeRange, limit: 20 }),
            engine.query<HttpEvent>(["http"], pairFilter, { timeRange, limit: 20 }),
            engine.query<DnsEvent>(["dns"], pairFilter, { timeRange, limit: 20 }),
            engine.query<TlsEvent>(["tls"], pairFilter, { timeRange, limit: 20 }),
          ]);

          relatedFlows.push(...flows);
          relatedHttp.push(...http);
          relatedDns.push(...dns);
          relatedTls.push(...tls);
        }

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              signatureId: args.signatureId,
              signature: alerts[0].alert.signature,
              category: alerts[0].alert.category,
              severity: alerts[0].alert.severity,
              alertCount: alerts.length,
              uniqueSources: new Set(alerts.map((a) => a.src_ip)).size,
              uniqueDestinations: new Set(alerts.map((a) => a.dest_ip)).size,
              alerts: alerts.slice(0, 20),
              relatedFlows: relatedFlows.slice(0, 20),
              relatedHttp: relatedHttp.slice(0, 20),
              relatedDns: relatedDns.slice(0, 20),
              relatedTls: relatedTls.slice(0, 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error investigating alert: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

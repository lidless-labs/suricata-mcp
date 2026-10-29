import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";
import { parseZeekFile, findZeekLog, type ZeekRecord } from "../parser/zeek.js";
import { matchesIp, matchesPartial, inTimeRange } from "../query/filters.js";
import { aggregate, topN, numericStats } from "../query/aggregation.js";

function zeekTsToIso(ts: string): string {
  const num = parseFloat(ts);
  if (isNaN(num)) return "";
  return new Date(num * 1000).toISOString();
}

function matchesZeekIp(record: ZeekRecord, field: string, ip: string): boolean {
  const val = record[field];
  if (!val) return false;
  return matchesIp(val, ip);
}

function matchesZeekPartial(record: ZeekRecord, field: string, pattern: string): boolean {
  const val = record[field];
  if (!val) return false;
  return matchesPartial(val, pattern);
}

function zeekTimeInRange(record: ZeekRecord, timeFrom?: string, timeTo?: string): boolean {
  const ts = record["ts"];
  if (!ts) return true;
  const iso = zeekTsToIso(ts);
  return inTimeRange(iso, timeFrom, timeTo);
}

export function registerZeekTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "zeek_query_connections",
    externalDescription("Search Zeek conn.log for network connections"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      srcPort: z.number().optional().describe("Source port"),
      dstPort: z.number().optional().describe("Destination port"),
      proto: z.string().optional().describe("Protocol: tcp, udp, icmp"),
      service: z.string().optional().describe("Service (partial match): dns, http, ssl, ssh"),
      minDuration: z.number().optional().describe("Minimum duration in seconds"),
      minBytes: z.number().optional().describe("Minimum total bytes (orig + resp)"),
      connState: z.string().optional().describe("Connection state: S0, S1, SF, REJ, etc."),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "conn.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "conn.log not found in Zeek logs directory." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.dstIp && !matchesZeekIp(r, "id.resp_h", args.dstIp)) return false;
            if (args.srcPort !== undefined && r["id.orig_p"] !== String(args.srcPort)) return false;
            if (args.dstPort !== undefined && r["id.resp_p"] !== String(args.dstPort)) return false;
            if (args.proto && r["proto"]?.toLowerCase() !== args.proto.toLowerCase()) return false;
            if (args.service && !matchesZeekPartial(r, "service", args.service)) return false;
            if (args.connState && r["conn_state"] !== args.connState) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            if (args.minDuration !== undefined) {
              const dur = parseFloat(r["duration"] ?? "0");
              if (isNaN(dur) || dur < args.minDuration) return false;
            }
            if (args.minBytes !== undefined) {
              const orig = parseInt(r["orig_bytes"] ?? "0", 10) || 0;
              const resp = parseInt(r["resp_bytes"] ?? "0", 10) || 0;
              if (orig + resp < args.minBytes) return false;
            }
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, connections: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek connections: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_dns",
    externalDescription("Search Zeek dns.log for DNS transactions"),
    {
      query: z.string().optional().describe("DNS query name (partial match)"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      qtype: z.string().optional().describe("Query type: A, AAAA, CNAME, MX, TXT, PTR"),
      rcode: z.string().optional().describe("Response code name: NOERROR, NXDOMAIN, SERVFAIL"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "dns.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "dns.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.query && !matchesZeekPartial(r, "query", args.query)) return false;
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.qtype && r["qtype_name"]?.toUpperCase() !== args.qtype.toUpperCase()) return false;
            if (args.rcode && r["rcode_name"]?.toUpperCase() !== args.rcode.toUpperCase()) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, dns: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek DNS: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_http",
    externalDescription("Search Zeek http.log for HTTP transactions"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      host: z.string().optional().describe("HTTP host (partial match)"),
      uri: z.string().optional().describe("URI path (partial match)"),
      method: z.string().optional().describe("HTTP method: GET, POST, PUT, etc."),
      statusCode: z.number().optional().describe("HTTP status code"),
      userAgent: z.string().optional().describe("User-Agent (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "http.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "http.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.host && !matchesZeekPartial(r, "host", args.host)) return false;
            if (args.uri && !matchesZeekPartial(r, "uri", args.uri)) return false;
            if (args.method && r["method"]?.toUpperCase() !== args.method.toUpperCase()) return false;
            if (args.statusCode !== undefined && r["status_code"] !== String(args.statusCode)) return false;
            if (args.userAgent && !matchesZeekPartial(r, "user_agent", args.userAgent)) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, http: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek HTTP: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_ssl",
    externalDescription("Search Zeek ssl.log for TLS/SSL connections"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      serverName: z.string().optional().describe("Server name / SNI (partial match)"),
      version: z.string().optional().describe("TLS version: TLSv12, TLSv13"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "ssl.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "ssl.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.dstIp && !matchesZeekIp(r, "id.resp_h", args.dstIp)) return false;
            if (args.serverName && !matchesZeekPartial(r, "server_name", args.serverName)) return false;
            if (args.version && r["version"] !== args.version) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, ssl: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek SSL: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_files",
    externalDescription("Search Zeek files.log for file transfer metadata"),
    {
      filename: z.string().optional().describe("Filename (partial match)"),
      mimeType: z.string().optional().describe("MIME type (partial match)"),
      md5: z.string().optional().describe("MD5 hash"),
      sha256: z.string().optional().describe("SHA256 hash"),
      source: z.string().optional().describe("Source protocol: HTTP, SSL, SMTP"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "files.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "files.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.filename && !matchesZeekPartial(r, "filename", args.filename)) return false;
            if (args.mimeType && !matchesZeekPartial(r, "mime_type", args.mimeType)) return false;
            if (args.md5 && r["md5"] !== args.md5) return false;
            if (args.sha256 && r["sha256"] !== args.sha256) return false;
            if (args.source && !matchesZeekPartial(r, "source", args.source)) return false;
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, files: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek files: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_ssh",
    externalDescription("Search Zeek ssh.log for SSH connection metadata"),
    {
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      dstIp: z.string().optional().describe("Destination IP (supports CIDR)"),
      client: z.string().optional().describe("Client software (partial match)"),
      server: z.string().optional().describe("Server software (partial match)"),
      authSuccess: z.boolean().optional().describe("Filter by authentication success"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "ssh.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "ssh.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.dstIp && !matchesZeekIp(r, "id.resp_h", args.dstIp)) return false;
            if (args.client && !matchesZeekPartial(r, "client", args.client)) return false;
            if (args.server && !matchesZeekPartial(r, "server", args.server)) return false;
            if (args.authSuccess !== undefined) {
              const val = r["auth_success"];
              if (args.authSuccess && val !== "T") return false;
              if (!args.authSuccess && val !== "F") return false;
            }
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, ssh: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek SSH: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_query_weird",
    externalDescription("Search Zeek weird.log for protocol anomalies"),
    {
      name: z.string().optional().describe("Weird event name (partial match)"),
      srcIp: z.string().optional().describe("Source IP (supports CIDR)"),
      source: z.string().optional().describe("Detection source: TCP, UDP, etc."),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().optional().describe("Max results (default 100)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "weird.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "weird.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          maxRecords: (args.limit ?? 100) * 10,
          filter: (r) => {
            if (args.name && !matchesZeekPartial(r, "name", args.name)) return false;
            if (args.srcIp && !matchesZeekIp(r, "id.orig_h", args.srcIp)) return false;
            if (args.source && !matchesZeekPartial(r, "source", args.source)) return false;
            if (!zeekTimeInRange(r, args.timeFrom, args.timeTo)) return false;
            return true;
          },
        });
        const limited = records.slice(0, args.limit ?? 100);
        return { content: [{ type: "text" as const, text: externalJson({ count: limited.length, weird: limited }, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error querying Zeek weird: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "zeek_connection_summary",
    externalDescription("Network connection summary from Zeek conn.log with top talkers and protocol distribution"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (args) => {
      try {
        if (!config.zeekLogsDir) {
          return { content: [{ type: "text" as const, text: "Zeek logs directory not configured. Set ZEEK_LOGS_DIR." }], isError: true };
        }
        const logPath = await findZeekLog(config.zeekLogsDir, "conn.log");
        if (!logPath) {
          return { content: [{ type: "text" as const, text: "conn.log not found." }], isError: true };
        }
        const { records } = await parseZeekFile(logPath, {
          filter: (r) => zeekTimeInRange(r, args.timeFrom, args.timeTo),
        });

        const topSources = topN(aggregate(records.map((r) => r["id.orig_h"] || "unknown")), 10);
        const topDests = topN(aggregate(records.map((r) => r["id.resp_h"] || "unknown")), 10);
        const protoDist = aggregate(records.map((r) => r["proto"] || "unknown"));
        const serviceDist = aggregate(records.filter((r) => r["service"]).map((r) => r["service"]));
        const connStates = aggregate(records.map((r) => r["conn_state"] || "unknown"));

        const origBytes = records.map((r) => parseInt(r["orig_bytes"] ?? "0", 10) || 0);
        const respBytes = records.map((r) => parseInt(r["resp_bytes"] ?? "0", 10) || 0);
        const totalOrig = origBytes.reduce((a, b) => a + b, 0);
        const totalResp = respBytes.reduce((a, b) => a + b, 0);
        const durations = records
          .map((r) => parseFloat(r["duration"] ?? "0"))
          .filter((d) => !isNaN(d) && d > 0);

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalConnections: records.length,
              totalOrigBytes: totalOrig,
              totalRespBytes: totalResp,
              durationStats: durations.length > 0 ? numericStats(durations) : null,
              topSources,
              topDestinations: topDests,
              protocolDistribution: protoDist,
              serviceDistribution: serviceDist,
              connectionStates: connStates,
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error generating Zeek connection summary: ${error}`) }], isError: true };
      }
    },
  );
}

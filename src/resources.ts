import { externalJson } from "./external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { QueryEngine } from "./query/engine.js";
import type { SuricataConfig } from "./config.js";
import type { StatsEvent } from "./types.js";
import { loadAllRules } from "./parser/rules.js";
import { aggregate } from "./query/aggregation.js";
import { readdir } from "node:fs/promises";

export function registerResources(
  server: McpServer,
  engine: QueryEngine,
  config: SuricataConfig,
): void {
  server.resource(
    "event-types",
    "suricata://event-types",
    async () => {
      const eventTypes = [
        { type: "alert", description: "IDS/IPS alert triggered by a rule match", keyFields: "signature_id, signature, severity, category, action, src_ip, dest_ip" },
        { type: "flow", description: "Network flow records with byte/packet counts", keyFields: "src_ip, dest_ip, proto, app_proto, bytes_toserver, bytes_toclient, state" },
        { type: "dns", description: "DNS transactions with query/response details", keyFields: "rrname, rrtype, rdata, rcode" },
        { type: "http", description: "HTTP transactions with full request/response metadata", keyFields: "hostname, url, http_method, status, http_user_agent" },
        { type: "tls", description: "TLS handshake information with JA3/JA4 fingerprints", keyFields: "sni, version, subject, issuer, ja3, ja4" },
        { type: "fileinfo", description: "File extraction metadata with hashes", keyFields: "filename, magic, md5, sha256, size" },
        { type: "smtp", description: "SMTP transaction details", keyFields: "mail_from, rcpt_to, helo" },
        { type: "ssh", description: "SSH protocol version information", keyFields: "client.software_version, server.software_version" },
        { type: "anomaly", description: "Protocol anomalies and malformed packets", keyFields: "type, event, layer" },
        { type: "stats", description: "Engine performance and capture statistics", keyFields: "capture, decoder, detect, flow" },
        { type: "drop", description: "Dropped packets in IPS mode", keyFields: "alert fields + drop reason" },
      ];

      return {
        contents: [{
          uri: "suricata://event-types",
          mimeType: "application/json",
          text: JSON.stringify(eventTypes, null, 2),
        }],
      };
    },
  );

  server.resource(
    "stats-current",
    "suricata://stats/current",
    async () => {
      try {
        const stats = await engine.query<StatsEvent>(
          ["stats"],
          () => true,
          { limit: 1 },
        );

        const latest = stats.length > 0 ? stats[stats.length - 1] : null;

        return {
          contents: [{
            uri: "suricata://stats/current",
            mimeType: "application/json",
            text: externalJson(latest ? latest.stats : { message: "No stats available" }, null, 2),
          }],
        };
      } catch {
        return {
          contents: [{
            uri: "suricata://stats/current",
            mimeType: "application/json",
            text: externalJson({ error: "Failed to read stats" }),
          }],
        };
      }
    },
  );

  server.resource(
    "rules-summary",
    "suricata://rules/summary",
    async () => {
      try {
        if (!config.rulesDir) {
          return {
            contents: [{
              uri: "suricata://rules/summary",
              mimeType: "application/json",
              text: externalJson({ message: "Rules directory not configured" }),
            }],
          };
        }

        const rules = await loadAllRules(config.rulesDir);
        const enabled = rules.filter((r) => r.enabled).length;
        const byAction = aggregate(rules.map((r) => r.action));

        return {
          contents: [{
            uri: "suricata://rules/summary",
            mimeType: "application/json",
            text: externalJson({
              totalRules: rules.length,
              enabled,
              disabled: rules.length - enabled,
              byAction,
            }, null, 2),
          }],
        };
      } catch {
        return {
          contents: [{
            uri: "suricata://rules/summary",
            mimeType: "application/json",
            text: externalJson({ error: "Failed to read rules" }),
          }],
        };
      }
    },
  );

  server.resource(
    "config",
    "suricata://config",
    async () => {
      const sanitized = {
        evePath: config.evePath,
        eveArchiveDir: config.eveArchiveDir,
        rulesDir: config.rulesDir,
        maxResults: config.maxResults,
        unixSocket: config.unixSocket ? "(configured)" : null,
        zeekLogsDir: config.zeekLogsDir,
        pcapDir: config.pcapDir,
        mispUrl: config.mispUrl ? "(configured)" : null,
        thehiveUrl: config.thehiveUrl ? "(configured)" : null,
      };
      return {
        contents: [{
          uri: "suricata://config",
          mimeType: "application/json",
          text: externalJson(sanitized, null, 2),
        }],
      };
    },
  );

  server.resource(
    "zeek-log-types",
    "zeek://log-types",
    async () => {
      const logTypes = [
        { log: "conn.log", description: "TCP/UDP/ICMP connection records", keyFields: "id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state" },
        { log: "dns.log", description: "DNS queries and responses", keyFields: "query, qtype_name, rcode_name, answers, TTLs" },
        { log: "http.log", description: "HTTP request/response details", keyFields: "method, host, uri, user_agent, status_code, resp_mime_types" },
        { log: "ssl.log", description: "TLS/SSL handshake metadata", keyFields: "version, cipher, server_name, resumed, established, cert_chain_fps" },
        { log: "files.log", description: "File analysis results", keyFields: "source, mime_type, filename, md5, sha1, sha256, seen_bytes" },
        { log: "ssh.log", description: "SSH handshake and auth info", keyFields: "version, auth_success, auth_attempts, client, server, cipher_alg" },
        { log: "weird.log", description: "Protocol anomalies", keyFields: "name, addl, notice, peer, source" },
        { log: "x509.log", description: "X.509 certificate details", keyFields: "certificate.version, certificate.serial, certificate.subject, certificate.issuer" },
        { log: "notice.log", description: "Zeek notices and alerts", keyFields: "note, msg, sub, src, dst, p, n" },
        { log: "dhcp.log", description: "DHCP transactions", keyFields: "mac, assigned_addr, lease_time, host_name" },
        { log: "ntp.log", description: "NTP activity", keyFields: "version, mode, stratum, ref_id" },
      ];

      // Check which logs actually exist
      let availableLogs: string[] = [];
      if (config.zeekLogsDir) {
        try {
          availableLogs = await readdir(config.zeekLogsDir);
        } catch { /* ignore */ }
      }

      const enriched = logTypes.map((lt) => ({
        ...lt,
        available: availableLogs.includes(lt.log),
      }));

      return {
        contents: [{
          uri: "zeek://log-types",
          mimeType: "application/json",
          text: JSON.stringify(enriched, null, 2),
        }],
      };
    },
  );
}

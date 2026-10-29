import { externalJson, externalText, externalDescription } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { DnsEvent } from "../types.js";
import { inTimeRange } from "../query/filters.js";

export function shannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

export function extractDomainBase(fqdn: string): string {
  // Strip TLD and take the longest label as the candidate
  const parts = fqdn.split(".").filter(Boolean);
  if (parts.length <= 1) return fqdn;
  // Remove the TLD (last part)
  parts.pop();
  // Return the longest remaining label (often the DGA-generated part)
  return parts.reduce((longest, p) => (p.length > longest.length ? p : longest), "");
}

export interface DgaCandidate {
  domain: string;
  baseDomain: string;
  entropy: number;
  length: number;
  srcIp: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export function registerDgaDetectionTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_dga_detection",
    externalDescription("Detect potential DGA (Domain Generation Algorithm) domains using Shannon entropy analysis on DNS queries"),
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      entropyThreshold: z.number().optional().describe("Minimum entropy to flag as suspicious (default 3.5)"),
      minLength: z.number().optional().describe("Minimum domain label length to analyze (default 8)"),
      limit: z.number().optional().describe("Max results (default 50)"),
    },
    async (args) => {
      try {
        const threshold = args.entropyThreshold ?? 3.5;
        const minLen = args.minLength ?? 8;

        const dnsEvents = await engine.queryAll<DnsEvent>(
          ["dns"],
          (event) => {
            if (!event.dns.rrname) return false;
            return inTimeRange(event.timestamp, args.timeFrom, args.timeTo);
          },
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const domainMap = new Map<string, {
          domain: string;
          baseDomain: string;
          entropy: number;
          srcIps: Set<string>;
          count: number;
          firstSeen: string;
          lastSeen: string;
        }>();

        for (const event of dnsEvents) {
          const fqdn = event.dns.rrname!;
          const base = extractDomainBase(fqdn);

          if (base.length < minLen) continue;

          const entropy = shannonEntropy(base);
          if (entropy < threshold) continue;

          let entry = domainMap.get(fqdn);
          if (!entry) {
            entry = {
              domain: fqdn,
              baseDomain: base,
              entropy: Math.round(entropy * 1000) / 1000,
              srcIps: new Set(),
              count: 0,
              firstSeen: event.timestamp,
              lastSeen: event.timestamp,
            };
            domainMap.set(fqdn, entry);
          }

          entry.count++;
          if (event.src_ip) entry.srcIps.add(event.src_ip);
          if (event.timestamp < entry.firstSeen) entry.firstSeen = event.timestamp;
          if (event.timestamp > entry.lastSeen) entry.lastSeen = event.timestamp;
        }

        const candidates: DgaCandidate[] = Array.from(domainMap.values())
          .sort((a, b) => b.entropy - a.entropy)
          .slice(0, args.limit ?? 50)
          .map((e) => ({
            domain: e.domain,
            baseDomain: e.baseDomain,
            entropy: e.entropy,
            length: e.baseDomain.length,
            srcIp: Array.from(e.srcIps).join(", "),
            count: e.count,
            firstSeen: e.firstSeen,
            lastSeen: e.lastSeen,
          }));

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              totalDnsQueries: dnsEvents.length,
              suspiciousDomains: candidates.length,
              entropyThreshold: threshold,
              candidates,
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error detecting DGA domains: ${error}`) }], isError: true };
      }
    },
  );
}

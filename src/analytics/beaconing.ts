import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { QueryEngine } from "../query/engine.js";
import type { FlowEvent } from "../types.js";
import { inTimeRange } from "../query/filters.js";

export interface BeaconCandidate {
  srcIp: string;
  dstIp: string;
  dstPort: number;
  connectionCount: number;
  intervals: number[];
  avgInterval: number;
  stdDevInterval: number;
  jitter: number;
  confidence: number;
}

function calculateStdDev(values: number[], mean: number): number {
  if (values.length < 2) return 0;
  const squaredDiffs = values.map((v) => (v - mean) ** 2);
  return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / (values.length - 1));
}

function calculateJitter(intervals: number[]): number {
  if (intervals.length < 2) return 0;
  let jitterSum = 0;
  for (let i = 1; i < intervals.length; i++) {
    jitterSum += Math.abs(intervals[i] - intervals[i - 1]);
  }
  return jitterSum / (intervals.length - 1);
}

function calculateConfidence(
  connectionCount: number,
  jitter: number,
  avgInterval: number,
  stdDev: number,
): number {
  let score = 0;

  // More connections = higher confidence
  if (connectionCount >= 50) score += 30;
  else if (connectionCount >= 20) score += 20;
  else if (connectionCount >= 10) score += 10;

  // Low jitter relative to interval = higher confidence
  if (avgInterval > 0) {
    const jitterRatio = jitter / avgInterval;
    if (jitterRatio < 0.05) score += 35;
    else if (jitterRatio < 0.1) score += 25;
    else if (jitterRatio < 0.2) score += 15;
    else if (jitterRatio < 0.5) score += 5;
  }

  // Low coefficient of variation = higher confidence
  if (avgInterval > 0) {
    const cv = stdDev / avgInterval;
    if (cv < 0.05) score += 35;
    else if (cv < 0.1) score += 25;
    else if (cv < 0.2) score += 15;
    else if (cv < 0.5) score += 5;
  }

  return Math.min(score, 100);
}

export function registerBeaconingTools(
  server: McpServer,
  engine: QueryEngine,
): void {
  server.tool(
    "suricata_beaconing_detection",
    "Detect potential C2 beaconing patterns in flow data",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      minConnections: z.number().optional().describe("Minimum connections to analyze (default 10)"),
      jitterThreshold: z.number().optional().describe("Max jitter percentage for beacon detection (default 20)"),
    },
    async (args) => {
      try {
        const minConns = args.minConnections ?? 10;
        const jitterThresh = args.jitterThreshold ?? 20;

        const flows = await engine.queryAll<FlowEvent>(
          ["flow"],
          (event) => inTimeRange(event.timestamp, args.timeFrom, args.timeTo),
          { timeRange: { timeFrom: args.timeFrom, timeTo: args.timeTo } },
        );

        const result = detectBeaconingCandidates(flows, minConns, jitterThresh);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalFlowsAnalyzed: flows.length,
              uniquePairsAnalyzed: result.uniquePairsAnalyzed,
              beaconCandidates: result.candidates.length,
              candidates: result.candidates.slice(0, 20),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error detecting beaconing: ${error}` }],
          isError: true,
        };
      }
    },
  );
}

export function detectBeaconingCandidates(
  flows: FlowEvent[],
  minConnections = 10,
  jitterThreshold = 20,
): { uniquePairsAnalyzed: number; candidates: BeaconCandidate[] } {
  const groups = new Map<string, { timestamps: number[]; srcIp: string; dstIp: string; dstPort: number }>();

  for (const flow of flows) {
    if (!flow.src_ip || !flow.dest_ip) continue;
    const key = `${flow.src_ip}->${flow.dest_ip}:${flow.dest_port ?? 0}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        timestamps: [],
        srcIp: flow.src_ip,
        dstIp: flow.dest_ip,
        dstPort: flow.dest_port ?? 0,
      };
      groups.set(key, group);
    }
    group.timestamps.push(new Date(flow.timestamp).getTime());
  }

  const candidates: BeaconCandidate[] = [];

  for (const group of groups.values()) {
    if (group.timestamps.length < minConnections) continue;

    group.timestamps.sort((a, b) => a - b);

    const intervals: number[] = [];
    for (let i = 1; i < group.timestamps.length; i++) {
      intervals.push((group.timestamps[i] - group.timestamps[i - 1]) / 1000);
    }

    if (intervals.length === 0) continue;

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (avgInterval < 1) continue;

    const stdDev = calculateStdDev(intervals, avgInterval);
    const jitter = calculateJitter(intervals);
    const jitterPercent = avgInterval > 0 ? (jitter / avgInterval) * 100 : 100;

    if (jitterPercent > jitterThreshold) continue;

    const confidence = calculateConfidence(
      group.timestamps.length,
      jitter,
      avgInterval,
      stdDev,
    );

    if (confidence >= 20) {
      candidates.push({
        srcIp: group.srcIp,
        dstIp: group.dstIp,
        dstPort: group.dstPort,
        connectionCount: group.timestamps.length,
        intervals: intervals.slice(0, 10),
        avgInterval: Math.round(avgInterval * 100) / 100,
        stdDevInterval: Math.round(stdDev * 100) / 100,
        jitter: Math.round(jitterPercent * 100) / 100,
        confidence,
      });
    }
  }

  candidates.sort((a, b) => b.confidence - a.confidence);

  return {
    uniquePairsAnalyzed: groups.size,
    candidates,
  };
}

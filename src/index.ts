import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { QueryEngine } from "./query/engine.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerFlowTools } from "./tools/flows.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerHttpTools } from "./tools/http.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerFileTools } from "./tools/files.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerAnomalyTools } from "./tools/anomalies.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerStatsTools } from "./tools/stats.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerBeaconingTools } from "./analytics/beaconing.js";
import { registerDgaDetectionTools } from "./analytics/dns_entropy.js";
import { registerExfiltrationTools } from "./analytics/exfiltration.js";
import { registerLateralMovementTools } from "./analytics/lateral.js";
import { registerSocketTools } from "./socket/client.js";
import { registerZeekTools } from "./tools/zeek.js";
import { registerPcapTools } from "./tools/pcap.js";
import { registerThreatIntelTools } from "./tools/threatintel.js";
import { registerCorrelationTools } from "./tools/correlation.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const server = new McpServer({
  name: "suricata-mcp",
  version: "2.0.0",
  description:
    "MCP server for Suricata IDS/IPS and Zeek NSM log analysis, threat hunting, and incident response",
});

const config = getConfig();
const engine = new QueryEngine(config);

// Alert analysis
registerAlertTools(server, engine);

// Flow analysis
registerFlowTools(server, engine);
registerBeaconingTools(server, engine);

// Protocol analysis
registerDnsTools(server, engine);
registerHttpTools(server, engine);
registerTlsTools(server, engine);
registerSshTools(server, engine);

// File and anomaly analysis
registerFileTools(server, engine);
registerAnomalyTools(server, engine);

// Rule management
registerRuleTools(server, config);

// Engine stats
registerStatsTools(server, engine);

// Cross-type investigation
registerInvestigationTools(server, engine);

// Advanced analytics
registerDgaDetectionTools(server, engine);
registerExfiltrationTools(server, engine);
registerLateralMovementTools(server, engine);

// Zeek integration
registerZeekTools(server, config);

// PCAP management
registerPcapTools(server, config);

// Threat intel (MISP + TheHive)
registerThreatIntelTools(server, config);

// Cross-correlation (Suricata + Zeek)
registerCorrelationTools(server, engine, config);

// Live commands via Unix socket
registerSocketTools(server, config);

// Resources and prompts
registerResources(server, engine, config);
registerPrompts(server);

async function main() {
  const transport = new StdioServerTransport();
  // Strip the draft-07 `$schema` the MCP SDK stamps on tool schemas; Anthropic
  // rejects it ("must match JSON Schema draft 2020-12") when the full tool set
  // is sent, e.g. on subagent spawns. Intercept tools/list output here.
  const __send = transport.send.bind(transport);
  (transport as any).send = (message: any) => {
    const tools = message?.result?.tools;
    if (Array.isArray(tools)) {
      for (const t of tools) {
        if (t?.inputSchema) delete t.inputSchema.$schema;
        if (t?.outputSchema) delete t.outputSchema.$schema;
      }
    }
    return __send(message);
  };
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

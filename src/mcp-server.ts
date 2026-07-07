import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { SuricataConfig } from "./config.js";
import { getConfig } from "./config.js";
import { registerBeaconingTools } from "./analytics/beaconing.js";
import { registerDgaDetectionTools } from "./analytics/dns_entropy.js";
import { registerExfiltrationTools } from "./analytics/exfiltration.js";
import { registerLateralMovementTools } from "./analytics/lateral.js";
import { registerPrompts } from "./prompts.js";
import { QueryEngine } from "./query/engine.js";
import { registerResources } from "./resources.js";
import { registerSocketTools } from "./socket/client.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerAnomalyTools } from "./tools/anomalies.js";
import { registerCorrelationTools } from "./tools/correlation.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerFileTools } from "./tools/files.js";
import { registerFlowTools } from "./tools/flows.js";
import { registerHttpTools } from "./tools/http.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerPcapTools } from "./tools/pcap.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerStatsTools } from "./tools/stats.js";
import { registerThreatIntelTools } from "./tools/threatintel.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerZeekTools } from "./tools/zeek.js";

export function createSuricataMcpServer(config: SuricataConfig = getConfig()): McpServer {
  const server = new McpServer({
    name: "suricata-mcp",
    version: "2.1.0",
    description:
      "MCP server for Suricata IDS/IPS and Zeek NSM log analysis, threat hunting, and incident response",
  });
  const engine = new QueryEngine(config);

  registerAlertTools(server, engine);
  registerFlowTools(server, engine);
  registerBeaconingTools(server, engine);
  registerDnsTools(server, engine);
  registerHttpTools(server, engine);
  registerTlsTools(server, engine);
  registerSshTools(server, engine);
  registerFileTools(server, engine);
  registerAnomalyTools(server, engine);
  registerRuleTools(server, config);
  registerStatsTools(server, engine);
  registerInvestigationTools(server, engine);
  registerDgaDetectionTools(server, engine);
  registerExfiltrationTools(server, engine);
  registerLateralMovementTools(server, engine);
  registerZeekTools(server, config);
  registerPcapTools(server, config);
  registerThreatIntelTools(server, config);
  registerCorrelationTools(server, engine, config);
  registerSocketTools(server, config);
  registerResources(server, engine, config);
  registerPrompts(server);

  return server;
}

export function stripDraftSchemaFromTransport(transport: StdioServerTransport): void {
  const send = transport.send.bind(transport);
  (transport as unknown as { send: typeof transport.send }).send = (message) => {
    const rpcMessage = message as { result?: { tools?: unknown } };
    const tools = rpcMessage.result?.tools;
    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (tool?.inputSchema) delete tool.inputSchema.$schema;
        if (tool?.outputSchema) delete tool.outputSchema.$schema;
      }
    }
    return send(message);
  };
}

export async function serveMcp(config: SuricataConfig = getConfig()): Promise<void> {
  const server = createSuricataMcpServer(config);
  const transport = new StdioServerTransport();
  stripDraftSchemaFromTransport(transport);
  await server.connect(transport);
}

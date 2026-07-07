export { getConfig, type SuricataConfig } from "./config.js";
export {
  createSuricataMcpServer,
  serveMcp,
  stripDraftSchemaFromTransport,
} from "./mcp-server.js";
export { QueryEngine, type QueryOptions } from "./query/engine.js";
export {
  detectBeaconingCandidates,
  type BeaconCandidate,
} from "./analytics/beaconing.js";
export type {
  AlertEvent,
  DnsEvent,
  EventType,
  EveEvent,
  FlowEvent,
} from "./types.js";

export interface SuricataConfig {
  evePath: string;
  eveArchiveDir: string;
  rulesDir: string | null;
  maxResults: number;
  unixSocket: string | null;
  zeekLogsDir: string | null;
  pcapDir: string | null;
  mispUrl: string | null;
  mispApiKey: string | null;
  thehiveUrl: string | null;
  thehiveApiKey: string | null;
  allowMutation: boolean;
}

export function getConfig(env: NodeJS.ProcessEnv = process.env): SuricataConfig {
  const maxResults = parseInt(env.SURICATA_MAX_RESULTS ?? "1000", 10);
  if (!Number.isFinite(maxResults) || maxResults < 1) {
    throw new Error(
      `Invalid SURICATA_MAX_RESULTS: "${env.SURICATA_MAX_RESULTS}". Must be a positive integer.`,
    );
  }

  return {
    evePath: env.SURICATA_EVE_LOG ?? "/var/log/suricata/eve.json",
    eveArchiveDir:
      env.SURICATA_EVE_ARCHIVE ?? "/var/log/suricata/",
    rulesDir: env.SURICATA_RULES_DIR ?? null,
    maxResults,
    unixSocket: env.SURICATA_UNIX_SOCKET ?? null,
    zeekLogsDir: env.ZEEK_LOGS_DIR ?? null,
    pcapDir: env.PCAP_DIR ?? null,
    mispUrl: env.MISP_URL ?? null,
    mispApiKey: env.MISP_API_KEY ?? null,
    thehiveUrl: env.THEHIVE_URL ?? null,
    thehiveApiKey: env.THEHIVE_API_KEY ?? null,
    allowMutation: env.SURICATA_ALLOW_MUTATION === "1",
  };
}

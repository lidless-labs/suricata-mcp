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

export function getConfig(): SuricataConfig {
  return {
    evePath: process.env.SURICATA_EVE_LOG ?? "/var/log/suricata/eve.json",
    eveArchiveDir:
      process.env.SURICATA_EVE_ARCHIVE ?? "/var/log/suricata/",
    rulesDir: process.env.SURICATA_RULES_DIR ?? null,
    maxResults: parseInt(process.env.SURICATA_MAX_RESULTS ?? "1000", 10),
    unixSocket: process.env.SURICATA_UNIX_SOCKET ?? null,
    zeekLogsDir: process.env.ZEEK_LOGS_DIR ?? null,
    pcapDir: process.env.PCAP_DIR ?? null,
    mispUrl: process.env.MISP_URL ?? null,
    mispApiKey: process.env.MISP_API_KEY ?? null,
    thehiveUrl: process.env.THEHIVE_URL ?? null,
    thehiveApiKey: process.env.THEHIVE_API_KEY ?? null,
    allowMutation: process.env.SURICATA_ALLOW_MUTATION === "1",
  };
}

import { externalJson, externalText, externalDescription, UPSTREAM_LIMITS } from "../external.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";
import { checkMutationAllowed } from "./mutation.js";

/** Only locally constructed errors may cross the credential-bearing boundary. */
class IntelBoundaryError extends Error {}

async function httpRequest(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  } = {},
): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  let response: Response | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let complete = false;
  // Race each I/O against one deadline: abort alone can wait on a stalled body.
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new IntelBoundaryError("Intel request timed out"));
      controller.abort();
    }, options.timeout ?? 30000);
  });

  try {
    response = await Promise.race([fetch(url, {
      method: options.method ?? "GET",
      headers: options.headers,
      body: options.body,
      signal: controller.signal,
      // Never resend credentials to a redirect target.
      redirect: "manual",
    }), deadline]);

    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      throw new IntelBoundaryError(`Intel endpoint redirect refused (HTTP ${response.status})`);
    }
    // Error bodies and Location/statusText may contain secrets. Never read/echo them.
    if (response.status < 200 || response.status >= 300) return { status: response.status, body: "" };
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > UPSTREAM_LIMITS.bytes)) {
      throw new IntelBoundaryError("Intel response exceeds upstream byte budget or has invalid Content-Length");
    }
    if (!response.body) { complete = true; return { status: response.status, body: "" }; }
    reader = response.body.getReader();
    // One fixed accumulator avoids retaining arbitrarily many tiny chunk objects.
    const buffer = Buffer.alloc(UPSTREAM_LIMITS.bytes);
    let bytes = 0;
    let fragments = 0;
    for (;;) {
      const chunk = await Promise.race([reader.read(), deadline]);
      if (chunk.done) break;
      if (++fragments > UPSTREAM_LIMITS.fragments || chunk.value.byteLength > UPSTREAM_LIMITS.bytes - bytes) {
        throw new IntelBoundaryError("Intel response exceeds upstream byte or fragment budget");
      }
      buffer.set(chunk.value, bytes);
      bytes += chunk.value.byteLength;
    }
    complete = true;
    return { status: response.status, body: new TextDecoder().decode(buffer.subarray(0, bytes)) };
  } catch (error) {
    throw error instanceof IntelBoundaryError ? error : new IntelBoundaryError("Intel request failed");
  } finally {
    clearTimeout(timer!);
    if (!complete) {
      controller.abort();
      // A producer's cancellation promise is not trusted to settle.
      const cancellation = reader ? reader.cancel() : response?.body?.cancel();
      void cancellation?.catch(() => {});
    }
    reader?.releaseLock();
  }
}

export function registerThreatIntelTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "misp_search_ioc",
    externalDescription("Search MISP threat intelligence platform for IOCs (IP, domain, hash)"),
    {
      value: z.string().describe("IOC value to search (IP, domain, or hash)"),
      type: z.enum(["ip-src", "ip-dst", "domain", "hostname", "md5", "sha256", "sha1", "url"]).optional().describe("IOC type (auto-detected if omitted)"),
      limit: z.number().optional().describe("Max results (default 25)"),
    },
    async (args) => {
      try {
        if (!config.mispUrl || !config.mispApiKey) {
          return { content: [{ type: "text" as const, text: "MISP not configured. Set MISP_URL and MISP_API_KEY." }], isError: true };
        }

        const searchBody: Record<string, unknown> = {
          value: args.value,
          limit: args.limit ?? 25,
          includeDecayScore: true,
        };
        if (args.type) {
          searchBody.type = args.type;
        }

        const result = await httpRequest(
          `${config.mispUrl}/attributes/restSearch`,
          {
            method: "POST",
            headers: {
              "Authorization": config.mispApiKey,
              "Content-Type": "application/json",
              "Accept": "application/json",
            },
            body: JSON.stringify(searchBody),
          },
        );

        if (result.status < 200 || result.status >= 300) {
          return {
            content: [{
              type: "text" as const,
              text: externalJson({ status: "error", httpStatus: result.status, message: "MISP request failed" }, null, 2),
            }],
            isError: true,
          };
        }

        let data: Record<string, unknown>;
        try {
          data = JSON.parse(result.body);
        } catch {
          return {
            content: [{ type: "text" as const, text: externalText(`MISP returned a non-JSON response (HTTP ${result.status}).`) }],
            isError: true,
          };
        }
        const attributes = ((data as { response?: { Attribute?: Record<string, unknown>[] } })?.response?.Attribute ?? []) as Record<string, unknown>[];

        return {
          content: [{
            type: "text" as const,
            text: externalJson({
              query: args.value,
              matchCount: attributes.length,
              attributes: attributes.map((a: Record<string, unknown>) => ({
                id: a.id,
                type: a.type,
                category: a.category,
                value: a.value,
                comment: a.comment,
                eventId: a.event_id,
                timestamp: a.timestamp,
                toIds: a.to_ids,
              })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error searching MISP: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "thehive_create_case",
    externalDescription("Create a new case in TheHive from investigation findings"),
    {
      confirm: z.boolean().optional().describe("Must be true to create in TheHive"),
      title: z.string().describe("Case title"),
      description: z.string().describe("Case description (supports markdown)"),
      severity: z.number().min(1).max(4).optional().describe("1=Low, 2=Medium, 3=High, 4=Critical"),
      tlp: z.number().min(0).max(4).optional().describe("TLP level: 0=Clear, 1=Green, 2=Amber, 3=Amber+Strict, 4=Red"),
      tags: z.array(z.string()).optional().describe("Case tags"),
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    async (args) => {
      try {
        const gate = checkMutationAllowed(config, args, "create a TheHive case");
        if (!gate.allowed) return gate.response;
        if (!config.thehiveUrl || !config.thehiveApiKey) {
          return { content: [{ type: "text" as const, text: "TheHive not configured. Set THEHIVE_URL and THEHIVE_API_KEY." }], isError: true };
        }

        const caseBody = {
          title: args.title,
          description: args.description,
          severity: args.severity ?? 2,
          tlp: args.tlp ?? 2,
          tags: args.tags ?? ["suricata-mcp"],
          flag: false,
        };

        const result = await httpRequest(
          `${config.thehiveUrl}/api/case`,
          {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${config.thehiveApiKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(caseBody),
          },
        );

        if (result.status >= 200 && result.status < 300) {
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(result.body);
          } catch {
            return {
              content: [{ type: "text" as const, text: externalText(`TheHive returned a non-JSON response (HTTP ${result.status}).`) }],
              isError: true,
            };
          }
          return {
            content: [{
              type: "text" as const,
              text: externalJson({
                status: "created",
                caseId: data._id ?? data.id,
                caseNumber: data.caseId ?? data.number,
                title: data.title,
              }, null, 2),
            }],
          };
        }

        return {
          content: [{
            type: "text" as const,
            text: externalJson({ status: "error", httpStatus: result.status, message: "TheHive case creation failed" }, null, 2),
          }],
          isError: true,
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error creating TheHive case: ${error}`) }], isError: true };
      }
    },
  );

  server.tool(
    "thehive_create_alert",
    externalDescription("Push a Suricata alert to TheHive as an alert for triage"),
    {
      confirm: z.boolean().optional().describe("Must be true to create in TheHive"),
      title: z.string().describe("Alert title"),
      description: z.string().describe("Alert description"),
      severity: z.number().min(1).max(4).optional().describe("1=Low, 2=Medium, 3=High, 4=Critical"),
      source: z.string().optional().describe("Alert source (default: suricata-mcp)"),
      sourceRef: z.string().optional().describe("Source reference (e.g., SID or flow_id)"),
      type: z.string().optional().describe("Alert type (default: suricata)"),
      tags: z.array(z.string()).optional().describe("Alert tags"),
      artifacts: z.array(z.object({
        dataType: z.string().describe("Artifact type: ip, domain, hash, url, filename"),
        data: z.string().describe("Artifact value"),
        message: z.string().optional().describe("Artifact description"),
        tlp: z.number().optional().describe("TLP level"),
      })).optional().describe("Observable artifacts"),
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    async (args) => {
      try {
        const gate = checkMutationAllowed(config, args, "create a TheHive alert");
        if (!gate.allowed) return gate.response;
        if (!config.thehiveUrl || !config.thehiveApiKey) {
          return { content: [{ type: "text" as const, text: "TheHive not configured. Set THEHIVE_URL and THEHIVE_API_KEY." }], isError: true };
        }

        const alertBody = {
          title: args.title,
          description: args.description,
          severity: args.severity ?? 2,
          source: args.source ?? "suricata-mcp",
          sourceRef: args.sourceRef ?? `mcp-${Date.now()}`,
          type: args.type ?? "suricata",
          tags: args.tags ?? ["suricata-mcp", "auto-generated"],
          artifacts: (args.artifacts ?? []).map((a) => ({
            dataType: a.dataType,
            data: a.data,
            message: a.message ?? "",
            tlp: a.tlp ?? 2,
          })),
        };

        const result = await httpRequest(
          `${config.thehiveUrl}/api/alert`,
          {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${config.thehiveApiKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(alertBody),
          },
        );

        if (result.status >= 200 && result.status < 300) {
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(result.body);
          } catch {
            return {
              content: [{ type: "text" as const, text: externalText(`TheHive returned a non-JSON response (HTTP ${result.status}).`) }],
              isError: true,
            };
          }
          return {
            content: [{
              type: "text" as const,
              text: externalJson({
                status: "created",
                alertId: data._id ?? data.id,
                title: data.title,
                source: data.source,
              }, null, 2),
            }],
          };
        }

        return {
          content: [{
            type: "text" as const,
            text: externalJson({ status: "error", httpStatus: result.status, message: "TheHive alert creation failed" }, null, 2),
          }],
          isError: true,
        };
      } catch (error) {
        return { content: [{ type: "text" as const, text: externalText(`Error creating TheHive alert: ${error}`) }], isError: true };
      }
    },
  );
}

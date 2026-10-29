import { externalJson, externalText, externalDescription, UPSTREAM_LIMITS } from "../external.js";
import { createConnection } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SuricataConfig } from "../config.js";
import { checkMutationAllowed } from "../tools/mutation.js";

function sendCommand(
  socketPath: string,
  command: string,
  args?: Record<string, string>,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let socket: ReturnType<typeof createConnection>;
    try { socket = createConnection(socketPath); }
    catch { reject(new Error("Socket command failed")); return; }
    const buffer = Buffer.alloc(UPSTREAM_LIMITS.bytes);
    let bytes = 0;
    let fragments = 0;
    let settled = false;
    const finish = (error?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.setTimeout(0);
      socket.removeListener("connect", onConnect);
      socket.removeListener("data", onData);
      socket.removeListener("end", onEnd);
      socket.removeListener("error", onError);
      socket.removeListener("timeout", onTimeout);
      socket.removeListener("close", onClose);
      socket.destroy();
      if (error) reject(new Error(error));
      else resolve(buffer.toString("utf8", 0, bytes));
    };
    const onConnect = () => {
      if (settled) return;
      const cmd = args ? JSON.stringify({ command, arguments: args }) : JSON.stringify({ command });
      try { socket.write(cmd); } catch { finish("Socket command failed"); }
    };
    const onData = (chunk: Buffer) => {
      if (settled) return;
      // Count raw bytes before retaining anything, including zero-byte fragments.
      if (++fragments > UPSTREAM_LIMITS.fragments || chunk.byteLength > UPSTREAM_LIMITS.bytes - bytes) {
        finish("Socket response exceeds upstream byte or fragment budget");
        return;
      }
      buffer.set(chunk, bytes);
      bytes += chunk.byteLength;
    };
    const onEnd = () => finish();
    const onError = () => finish("Socket command failed");
    const onClose = () => finish("Socket closed before response completed");
    const onTimeout = () => finish("Socket command timed out");
    // Keep both idle and absolute deadlines. Continuous data cannot extend the latter.
    const timer = setTimeout(onTimeout, 10000);
    socket.once("connect", onConnect);
    socket.on("data", onData);
    socket.once("end", onEnd);
    socket.once("error", onError);
    socket.once("close", onClose);
    socket.on("timeout", onTimeout);
    socket.setTimeout(10000);
  });
}

export function registerSocketTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "suricata_reload_rules",
    externalDescription("Trigger a live rule reload via Suricata Unix socket (requires SURICATA_ALLOW_MUTATION=1 and confirm:true)"),
    { confirm: z.boolean().optional().describe("Must be true to reload rules") },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    async (args) => {
      try {
        const gate = checkMutationAllowed(config, args, "reload Suricata rules");
        if (!gate.allowed) return gate.response;
        if (!config.unixSocket) {
          return {
            content: [{ type: "text" as const, text: "Unix socket not configured. Set SURICATA_UNIX_SOCKET." }],
            isError: true,
          };
        }

        const result = await sendCommand(config.unixSocket, "reload-rules");
        return {
          content: [{ type: "text" as const, text: externalJson({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error reloading rules: ${error}`) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_iface_stat",
    externalDescription("Get interface capture statistics from Suricata"),
    {
      iface: z.string().optional().describe("Interface name (e.g., eth0)"),
    },
    async (args) => {
      try {
        if (!config.unixSocket) {
          return {
            content: [{ type: "text" as const, text: "Unix socket not configured. Set SURICATA_UNIX_SOCKET." }],
            isError: true,
          };
        }

        const cmdArgs = args.iface ? { iface: args.iface } : undefined;
        const result = await sendCommand(config.unixSocket, "iface-stat", cmdArgs);
        return {
          content: [{ type: "text" as const, text: externalJson({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: externalText(`Error getting interface stats: ${error}`) }],
          isError: true,
        };
      }
    },
  );
}

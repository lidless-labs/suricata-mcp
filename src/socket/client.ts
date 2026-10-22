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
    const socket = createConnection(socketPath, () => {
      // Suricata expects JSON commands on its Unix socket
      const cmd = args
        ? JSON.stringify({ command, arguments: args })
        : JSON.stringify({ command });
      socket.write(cmd);
    });

    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
    });

    socket.on("end", () => {
      resolve(data);
    });

    socket.on("error", (err) => {
      reject(new Error(`Socket error: ${err.message}`));
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      reject(new Error("Socket command timed out"));
    });
  });
}

export function registerSocketTools(
  server: McpServer,
  config: SuricataConfig,
): void {
  server.tool(
    "suricata_reload_rules",
    "Trigger a live rule reload via Suricata Unix socket (requires SURICATA_ALLOW_MUTATION=1 and confirm:true)",
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
          content: [{ type: "text" as const, text: JSON.stringify({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error reloading rules: ${error}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_iface_stat",
    "Get interface capture statistics from Suricata",
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
          content: [{ type: "text" as const, text: JSON.stringify({ status: "success", response: result }, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error getting interface stats: ${error}` }],
          isError: true,
        };
      }
    },
  );
}

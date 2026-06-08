import type { SuricataConfig } from "../config.js";

/**
 * Result of a mutation gate check. When `allowed` is false, `response` holds a
 * ready-to-return MCP error payload explaining why the destructive/mutating
 * operation was refused.
 */
export type MutationGate =
  | { allowed: true }
  | {
      allowed: false;
      response: {
        content: Array<{ type: "text"; text: string }>;
        isError: true;
      };
    };

/**
 * Gate a destructive/mutating tool behind an explicit opt-in.
 *
 * Two independent guards must both be satisfied:
 *  - `SURICATA_ALLOW_MUTATION=1` must be set in the environment (operator opt-in).
 *  - The caller must pass `confirm: true` on the tool invocation (model opt-in).
 *
 * This keeps read-only analysis the safe default and requires an explicit,
 * auditable choice before the server mutates a live IDS or shells out.
 */
export function checkMutationAllowed(
  config: SuricataConfig,
  args: { confirm?: boolean },
  action: string,
): MutationGate {
  if (!config.allowMutation) {
    return {
      allowed: false,
      response: {
        content: [{
          type: "text" as const,
          text:
            `Refusing to ${action}: mutating tools are disabled. ` +
            "Set SURICATA_ALLOW_MUTATION=1 in the server environment to enable them.",
        }],
        isError: true,
      },
    };
  }

  if (args.confirm !== true) {
    return {
      allowed: false,
      response: {
        content: [{
          type: "text" as const,
          text:
            `Refusing to ${action}: this is a destructive operation. ` +
            "Re-invoke with confirm: true to proceed.",
        }],
        isError: true,
      },
    };
  }

  return { allowed: true };
}

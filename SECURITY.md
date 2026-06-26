# Security Policy

## Supported versions

suricata-mcp follows semantic versioning. Only the latest released minor on the `main` branch receives security fixes. Pin to a released tag if you need a known-good version.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Use [GitHub private vulnerability reporting](https://github.com/lidless-labs/suricata-mcp/security/advisories/new) with:

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version or commit you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up.

## In scope

- Command injection, path traversal, or symlink-attack flaws in any tool that reads files or shells out (`suricata_create_rule`, `suricata_reload_rules_docker`, `pcap_replay_suricata`, `pcap_replay_zeek`).
- Bypasses of the mutation guard: any path where a mutating tool acts without both `SURICATA_ALLOW_MUTATION=1` **and** a per-call `confirm: true`.
- Leakage of a configured `MISP_API_KEY` or `THEHIVE_API_KEY`, including following a 3xx redirect from a threat-intel endpoint with the key attached (the client uses `redirect: "manual"` specifically to refuse this).
- SID-range or ruleset-collision bypasses in `suricata_create_rule` (it enforces `sid >= 1000000` and rejects collisions with the loaded ruleset).
- Filename option-injection in PCAP replay (filenames are basename-sanitized and rejected if they begin with `-`).
- Denial of service through a malformed EVE JSON or Zeek log that the streaming parsers mishandle.

## Out of scope

- Vulnerabilities in Suricata, Zeek, MISP, or TheHive themselves. Report those to their respective projects.
- Vulnerabilities in the MCP client (Claude Desktop, Claude Code, Codex CLI, OpenClaw, Hermes) that runs this server.
- Issues that require an attacker to already have read or write access to the host running the server, its log files, or its environment variables.
- Misconfiguration where an operator deliberately points the server at untrusted log files or enables mutation in an exposed environment.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.

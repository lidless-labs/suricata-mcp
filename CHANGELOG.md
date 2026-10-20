# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `suricata_reload_rules_docker`, `pcap_replay_suricata`, and `pcap_replay_zeek` no longer build shell command strings. They call `docker` through `execFile` with argv arrays, so no value is ever interpreted by a shell. The reload step now reads the Suricata pid with a separate call and refuses to signal unless it is purely numeric.
- PCAP replay filenames are validated against a strict allowlist (letters, digits, `.`, `-`, `_`) and rejected when they do not match, instead of being silently rewritten. Names containing path separators or shell metacharacters now return `Invalid filename`.
- Added regression tests: `suricata_toggle_rule` performs no write when the confirm or mutation gate refuses, and hostile filenames (`;`, `$(...)`, backticks, pipes, path traversal) never reach the command runner.

### Changed
- README rewritten to the OSS adoption standard: the opening three sentences state what the server is, why it exists, and how it differs; a `npx -y suricata-mcp` MCP client config block is the lead proof; badges use the `for-the-badge` style and point at the `lidless-labs` repo; a prominent link to the project website was added; the stale "36 tools" count was corrected to the real 41 registered tools; and "Why not query the logs directly?" and "What suricata-mcp is not" sections were added.

### Added
- Maintainer-health files: `SECURITY.md` (vulnerability reporting, in/out-of-scope, disclosure window), `CONTRIBUTING.md` (contribution path, local dev, how to add a tool), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `.github/ISSUE_TEMPLATE/` bug and feature forms with `blank_issues_enabled: false` and contact links, `.github/PULL_REQUEST_TEMPLATE.md` with a no-PII / content-guard checkbox, and this changelog.

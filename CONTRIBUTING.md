# Contributing to suricata-mcp

suricata-mcp is an MCP server that exposes Suricata IDS/IPS and Zeek NSM telemetry to AI clients. Patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## What kinds of changes land easily

- **Bug fixes** in the EVE JSON / Zeek parsers, the query and aggregation engine, the analytics (beaconing, DGA, exfiltration, lateral movement), or any tool handler.
- **New query filters or aggregations** on existing event types, with tests.
- **Better tool descriptions or input schemas** that make a tool easier for a model to call correctly.
- **Sharper docs**: clearer client wiring, configuration notes, or examples.
- **Test coverage** for any of the above.

## What needs a conversation first

- **A new tool, resource, or prompt.** Open an issue first describing the user story. The tool surface is the public contract, and renaming or splitting a tool later breaks every client config that references it.
- **Breaking changes** to a tool name, its input schema, or an environment variable.
- **Anything that adds a runtime dependency.** The server ships with only `@modelcontextprotocol/sdk` and `zod` on purpose. New runtime deps need justification.
- **Anything that loosens the mutation guard** (`SURICATA_ALLOW_MUTATION` + per-call `confirm`). Both guards exist by design.

## What does not land

- Personal details, hostnames, real IP addresses, account IDs, or live credentials in code, tests, or fixtures. Use `192.0.2.0/24` (RFC 5737) and generic names like `misp.local`. The content-guard pre-push hook and CI will fail if it finds any.
- Tools that call out to the network without an explicit operator opt-in. The MISP/TheHive clients are the only network egress, and they only run when their URL and key are configured.
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local dev

```bash
git clone https://github.com/lidless-labs/suricata-mcp.git
cd suricata-mcp
npm install
npm run build
npm test            # 158 tests
npm run lint        # type-check
```

To run the server against the bundled sample data:

```bash
SURICATA_EVE_LOG=test-data/eve.json \
SURICATA_RULES_DIR=test-data \
ZEEK_LOGS_DIR=test-data \
node dist/index.js
```

`npm run generate-eve` regenerates the mock EVE fixtures.

## Adding a tool

Tools live under `src/tools/` (and `src/analytics/` for the detectors) and are registered with `server.tool(name, description, schema, handler)`. To add one:

1. Implement the handler in the appropriate `src/tools/<area>.ts` module.
2. Define its input schema with `zod`.
3. Register it where its sibling tools are registered, and ensure `src/index.ts` wires the module in.
4. If it mutates state or shells out, gate it behind `SURICATA_ALLOW_MUTATION` **and** a `confirm: true` input, matching the existing mutating tools.
5. Add tests under `tests/`.
6. Add a row to the relevant tool table in `README.md` and bump the tool count.

## Filing issues

Please use the templates under `.github/ISSUE_TEMPLATE/`. They exist to save you from re-typing the version and config shape every time. Before posting output, remove tokens, private hostnames, and real IP addresses.

## License

By contributing you agree that your contribution is licensed under the MIT License, same as the rest of the repo.

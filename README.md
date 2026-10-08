# mcp-server-core

The platform-agnostic core shared by Deployment Theory's desktop MCP servers
([windows-mcp-server](https://github.com/deploymenttheory/windows-mcp-server)
and [macos-mcp-server](https://github.com/deploymenttheory/macos-mcp-server)).

Everything a desktop-automation MCP server needs that is not about one
operating system lives here, so the two servers cannot drift apart on the
protocol, the toolset engine, the guardrail wiring or the journey runner:

| Package | What it holds |
|---|---|
| `inventory` | The toolset filter/registration engine (modelled on github-mcp-server): toolsets, personas as presets, `--tools`/`--exclude-tools`, fixed resources, prompts. |
| `toolkit` | Tool-handler building blocks: argument coercion (`ArgsMap`, `Optional*`), result constructors, the assertion algebra, protected-path guards, the evidence sink, the planner contract, and generic dependency injection (`MustDepsFromContext[D]`). |
| `surface` | One constructor for the MCP server every entry point shares (stdio, offline capture, conformance host), the single-call receiving-middleware chain, SEP-2549 cache hints, pinned capabilities, completion, the wire recorder. |
| `runtime` | Guardrail orchestration over [agentweave-harness](https://github.com/deploymenttheory/agentweave-harness): policy loading, the signal registry, the receiving chain, egress provisioning (enforcer injected), the harness servant (dialer injected), the planner, the journey runner, evidence sealing and export, and the operator-facing policy operations. |
| `journeys`, `runrecord` | Journeys-as-code: the document vocabulary, compilation to a plan, and the OTLP/JSON run record. |
| `mcpspec`, `mcpconf` | The vendored MCP schema loader (offline wire validation) and the official conformance-suite results reader. |
| `conformance` (`-tags conformance`) | The suite's named fixtures and the generic loopback Streamable-HTTP host. Never part of a normal build. |

## Rules

- **No platform build tags.** CI refuses them. A server supplies its platform
  through the agentweave-harness interfaces (`signals.SystemProbe`,
  `signals.HealthProbe`, `contain.SystemActuator`, `egress.Enforcer`) and its
  own dependency type.
- **Secrets come from the environment**, named by `runtime.EnvNames{Prefix}`
  so each server keeps its own prefix (`WINDOWS_MCP_`, `MACOS_MCP_`).
- **Pin tags, never `replace`.** The servers import this module by tag; CI
  refuses a `replace` directive.

## Protocol

Targets MCP revision **2026-07-28** on `modelcontextprotocol/go-sdk`. The
revisions this module vendors for offline validation are listed in
`schema/versions.json`.

## License

MIT — see [LICENSE](LICENSE).

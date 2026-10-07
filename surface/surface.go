// Package surface builds the protocol-facing MCP server every entry point of a
// server shares: the stdio server operators run, the in-process capture used
// for the offline pre-flight, and the loopback HTTP host the official
// conformance suite connects to.
//
// It exists so those three cannot drift. Conformance evidence gathered against
// the HTTP host only transfers to the shipped stdio binary if both serve the
// same manifest, the same capabilities and the same instructions, through the
// same middleware — and the cheapest way to guarantee that is for one function
// to build all of it.
package surface

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// Config names the server as it appears in server/discover.
type Config struct {
	// Name is the implementation name, e.g. "macos-mcp-server".
	Name string
	// Title is the human-readable name, e.g. "macOS MCP Server".
	Title string
	// Version is the build version stamped into the implementation info.
	Version string
}

// CompletionHandler is the completion/complete handler a surface serves.
type CompletionHandler = func(context.Context, *mcp.CompleteRequest) (*mcp.CompleteResult, error)

// Surface is the protocol-facing construction.
type Surface struct {
	Server *mcp.Server
	// Capabilities is the pinned capability set handed to the server, kept so the
	// rug-pull detector can baseline exactly what was advertised.
	Capabilities *mcp.ServerCapabilities
	// Instructions is the combined persona and toolset guidance, kept for the same
	// reason.
	Instructions string
	// deps backs the inject-deps layer, held until InstallReceiving runs because
	// the whole chain must be installed in a single call — see InstallReceiving.
	deps any
}

// New builds the server. It installs no middleware: every entry point must
// call InstallReceiving exactly once, with the layers that belong inside the
// two unconditional ones.
//
// deps is the server's dependency set, injected into every request's context.
// completer serves completion/complete; see CompletionHandlerFor.
func New(
	cfg Config,
	inv *inventory.Inventory,
	personaInstructions string,
	deps any,
	completer CompletionHandler,
) *Surface {
	s := &Surface{
		Capabilities: PinnedCapabilities(),
		Instructions: CombineInstructions(personaInstructions, inv.Instructions()),
		deps:         deps,
	}
	s.Server = mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Title:   cfg.Title,
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions:      s.Instructions,
		Capabilities:      s.Capabilities,
		CompletionHandler: completer,
	})
	return s
}

// InstallReceiving installs the whole receiving chain, outermost first: inject
// deps, cache hints, then inner.
//
// It must be ONE call, and that is the entire reason this method exists.
// AddReceivingMiddleware composes the middleware handed to a single call
// outermost-first, but each separate call wraps the chain built so far — so
// across several calls the last middleware added ends up outermost, the reverse
// of the order intended. Installing across calls put the policy engine outside
// the audit layer, and a refused call therefore produced no tool.call entry at
// all: the refusals are precisely the events the chain exists to hold.
//
// Dependency injection has to be outermost for every other layer to read deps
// from the context, and the cache hints have to sit outside the guardrails so
// nothing inside can undo the envelope they set.
func (s *Surface) InstallReceiving(inner ...mcp.Middleware) {
	chain := make([]mcp.Middleware, 0, len(inner)+2)
	chain = append(chain, toolkit.InjectDepsMiddleware(s.deps), CacheHintsMiddleware())
	chain = append(chain, inner...)
	s.Server.AddReceivingMiddleware(chain...)
}

// PinnedCapabilities declares every server capability explicitly.
//
// This must stay explicit. The SDK *infers* capabilities it finds unset:
// registering a prompt or resource makes Server.capabilities() fill in
// Prompts/Resources with ListChanged: true. That would re-open exactly the silent
// re-advertisement channel the tools capability was pinned to close — a mutated
// manifest could be pushed to the client without the client re-listing, which is
// what rug-pull detection exists to catch. Any non-nil field we set wins over
// inference, so pinning each one with ListChanged false keeps the manifest static
// and drift detectable.
//
// Two fields are deliberately left unset. Extensions (added in 2026-07-28) stays
// absent because the server implements no protocol extension — declaring one it
// does not honour would be a false advertisement, and the rug-pull discover
// baseline trips if a future SDK starts populating it. Logging stays absent
// because SEP-2577 deprecated the feature and the servers log to stderr or a
// file, never as MCP notifications.
func PinnedCapabilities() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{
		Tools:       &mcp.ToolCapabilities{},
		Prompts:     &mcp.PromptCapabilities{},
		Resources:   &mcp.ResourceCapabilities{},
		Completions: &mcp.CompletionCapabilities{},
	}
}

// CombineInstructions joins the persona guidance and the toolset-derived
// instructions, omitting empty parts.
func CombineInstructions(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n\n")
}

// ToolsetIDs renders toolset metadata as its string IDs.
func ToolsetIDs(tss []inventory.ToolsetMetadata) []string {
	ids := make([]string, len(tss))
	for i, ts := range tss {
		ids[i] = string(ts.ID)
	}
	return ids
}

// MCPTools returns the registered tool definitions as []*mcp.Tool for
// fingerprinting.
func MCPTools(ctx context.Context, inv *inventory.Inventory) []*mcp.Tool {
	sts := inv.AvailableTools(ctx)
	out := make([]*mcp.Tool, 0, len(sts))
	for i := range sts {
		t := sts[i].Tool
		out = append(out, &t)
	}
	return out
}

// MCPPrompts returns the registered prompts as []*mcp.Prompt for fingerprinting.
func MCPPrompts(ctx context.Context, inv *inventory.Inventory) []*mcp.Prompt {
	sps := inv.AvailablePrompts(ctx)
	out := make([]*mcp.Prompt, 0, len(sps))
	for i := range sps {
		p := sps[i].Prompt
		out = append(out, &p)
	}
	return out
}

// MCPResources returns the registered fixed-URI resources as []*mcp.Resource
// for fingerprinting.
func MCPResources(ctx context.Context, inv *inventory.Inventory) []*mcp.Resource {
	srs := inv.AvailableResources(ctx)
	out := make([]*mcp.Resource, 0, len(srs))
	for i := range srs {
		res := srs[i].Resource
		out = append(out, &res)
	}
	return out
}

package surface

import (
	"context"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// maxCompletions bounds a completion response. The spec allows the server to
// truncate and report HasMore, which keeps a large tool manifest from dominating
// a completion payload.
const maxCompletions = 100

// CompletionSources is what a server knows that a completion may offer.
//
// Values come only from data the server already holds — persona IDs, toolset
// IDs, tool names, common application names, and configured credential *names*.
// It never sources a credential secret: the Credentials tool's never-read
// invariant applies here too, and a completion response goes straight into the
// model's context.
type CompletionSources struct {
	// PersonaIDs lists the built-in persona selectors.
	PersonaIDs []string
	// CommonApps are frequently automated applications, offered as launch
	// suggestions. Deliberately a short curated list rather than an enumeration
	// of installed software, which would be slow and leak the machine's inventory.
	CommonApps []string
}

// CompletionHandlerFor serves completion/complete for prompt arguments.
//
// The SDK validates that Ref and Argument.Name are present before dispatch, so
// this handler can assume both.
func CompletionHandlerFor(inv *inventory.Inventory, src CompletionSources) CompletionHandler {
	return func(ctx context.Context, req *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
		// Non-nil from the start. The spec requires completion.values to be an
		// array, and a nil slice marshals to `null` — which is what the conformance
		// suite's completion-complete scenario reports as "values is not an array".
		// Every path below has to preserve that, which is why filterByPrefix
		// returns an empty slice rather than passing nil through.
		values := []string{}

		// Only prompt arguments are completed; resource-URI completion would imply
		// enumerating live desktop state, which belongs behind a tool call.
		if req.Params.Ref != nil && req.Params.Ref.Type == "ref/prompt" {
			values = completionValues(ctx, inv, src, req.Params.Argument.Name)
		}

		values = filterByPrefix(values, req.Params.Argument.Value)
		total := len(values)
		hasMore := false
		if total > maxCompletions {
			values, hasMore = values[:maxCompletions], true
		}

		return &mcp.CompleteResult{
			Completion: mcp.CompletionResultDetails{
				Values:  values,
				Total:   total,
				HasMore: hasMore,
			},
		}, nil
	}
}

// completionValues resolves the candidate set for a prompt argument name.
func completionValues(ctx context.Context, inv *inventory.Inventory, src CompletionSources, argument string) []string {
	switch strings.ToLower(argument) {
	case "persona":
		out := slices.Clone(src.PersonaIDs)
		slices.Sort(out)
		return out

	case "toolset", "toolsets":
		ids := inv.ToolsetIDs()
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, string(id))
		}
		slices.Sort(out)
		return out

	case "tool":
		tools := inv.AvailableTools(ctx)
		out := make([]string, 0, len(tools))
		for i := range tools {
			out = append(out, tools[i].Tool.Name)
		}
		slices.Sort(out)
		return out

	case "app", "application":
		return slices.Clone(src.CommonApps)

	case "credential":
		// Names only — never a target's secret. DepsFromContext rather than the
		// Must variant: completion must degrade quietly if deps are absent.
		deps, ok := toolkit.DepsFromContext[toolkit.ToolDependencies](ctx)
		if !ok {
			return nil
		}
		creds := deps.Credentials()
		out := make([]string, 0, len(creds))
		for _, c := range creds {
			out = append(out, c.Name)
		}
		slices.Sort(out)
		return out
	}
	return nil
}

// filterByPrefix narrows the suggestions to those the caller has started typing,
// case-insensitively.
//
// It never returns nil: completion.values must be a JSON array, and returning a
// nil slice anywhere on this path puts `null` on the wire.
func filterByPrefix(values []string, typed string) []string {
	if values == nil {
		return []string{}
	}
	if typed == "" {
		return values
	}
	lower := strings.ToLower(typed)
	out := values[:0:0]
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v), lower) {
			out = append(out, v)
		}
	}
	return out
}

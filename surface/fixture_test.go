package surface

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// A tiny, platform-free manifest: enough tools, toolsets and a prompt to
// exercise the surface the way a real server's manifest does.
var (
	tsScreen = inventory.ToolsetMetadata{ID: "screen", Description: "perception", Default: true}
	tsShell  = inventory.ToolsetMetadata{ID: "shell", Description: "execution"}
	tsFiles  = inventory.ToolsetMetadata{ID: "filesystem", Description: "files"}
)

type fixtureDeps interface{ toolkit.ToolDependencies }

func fixtureTool(name string, ts inventory.ToolsetMetadata, readOnly bool) inventory.ServerTool {
	destructive := !readOnly
	return toolkit.NewToolFromHandler[fixtureDeps](ts, mcp.Tool{
		Name: name, Description: name + " tool",
		Annotations: &mcp.ToolAnnotations{Title: name, ReadOnlyHint: readOnly, DestructiveHint: &destructive},
		InputSchema: &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{
			"x": {Type: "string"},
		}},
	}, func(context.Context, fixtureDeps, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return toolkit.NewToolResultText("ok"), nil
	})
}

func fixturePrompt() inventory.ServerPrompt {
	return inventory.ServerPrompt{
		Prompt:  mcp.Prompt{Name: "rpa-journey", Arguments: []*mcp.PromptArgument{{Name: "persona"}}},
		Toolset: tsScreen,
		Handler: func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "go"}}}}, nil
		},
	}
}

func fixtureResource() inventory.ServerResource {
	return inventory.NewServerResource(tsScreen, mcp.Resource{
		Name: "state", URI: "fixture://state", MIMEType: "text/plain",
	}, func(any) mcp.ResourceHandler {
		return func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
				URI: "fixture://state", MIMEType: "text/plain", Text: "ready",
			}}}, nil
		}
	})
}

func fixtureInventory(t *testing.T, toolsets []string) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.NewBuilder().
		SetTools([]inventory.ServerTool{
			fixtureTool("Snapshot", tsScreen, true),
			fixtureTool("Shell", tsShell, false),
			fixtureTool("FileSystem", tsFiles, false),
		}).
		SetPrompts([]inventory.ServerPrompt{fixturePrompt()}).
		SetFixedResources([]inventory.ServerResource{fixtureResource()}).
		WithToolsets(toolsets).
		WithServerInstructions().
		Build()
	if err != nil {
		t.Fatalf("build fixture inventory: %v", err)
	}
	return inv
}

func fixtureMembership() map[string]string {
	return map[string]string{"Snapshot": "screen", "Shell": "shell", "FileSystem": "filesystem"}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newFixtureSurface builds a surface over the fixture manifest with the two
// unconditional layers installed, exactly as a capture does.
func newFixtureSurface(t *testing.T, toolsets []string, inner ...mcp.Middleware) (*Surface, *inventory.Inventory, *toolkit.BaseDeps) {
	t.Helper()
	inv := fixtureInventory(t, toolsets)
	deps := toolkit.NewBaseDeps(discardLogger(), nil)
	s := New(Config{Name: "fixture-server", Title: "Fixture", Version: "test"}, inv, "", deps,
		CompletionHandlerFor(inv, CompletionSources{PersonaIDs: []string{"qa", "support"}, CommonApps: []string{"TextEdit"}}))
	s.InstallReceiving(inner...)
	return s, inv, deps
}

func captureFixture(t *testing.T, toolsets []string) Captured {
	t.Helper()
	s, inv, deps := newFixtureSurface(t, toolsets)
	got, err := Capture(context.Background(), s, inv, deps, "test")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	return got
}

package surface

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/mcpspec"
)

func TestValidateCapturedChecksTheActualSurface(t *testing.T) {
	manifest, err := mcpspec.LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(schemaDir(), manifest.Newest())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFixture(t, []string{"all"})
	if err := ValidateCaptured(spec, got); err != nil {
		t.Fatalf("valid fixture surface: %v", err)
	}

	var listed map[string]json.RawMessage
	if err := json.Unmarshal(got.ToolsListResult, &listed); err != nil {
		t.Fatal(err)
	}
	var tools []map[string]any
	if err := json.Unmarshal(listed["tools"], &tools); err != nil {
		t.Fatal(err)
	}
	tools[0]["inputSchema"] = map[string]any{"type": "not-a-json-schema-type"}
	listed["tools"], err = json.Marshal(tools)
	if err != nil {
		t.Fatal(err)
	}
	got.ToolsListResult, err = json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCaptured(spec, got); err == nil || !strings.Contains(err.Error(), "inputSchema") {
		t.Fatalf("invalid advertised tool schema was accepted: %v", err)
	}
}

func TestProductMethodProbesValidateRawResponses(t *testing.T) {
	manifest, err := mcpspec.LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(schemaDir(), manifest.Newest())
	if err != nil {
		t.Fatal(err)
	}
	s, inv, deps := newFixtureSurface(t, []string{"all"})
	got, err := CaptureWithProbes(context.Background(), s, inv, deps, "test", func(ctx context.Context, client *mcp.ClientSession) error {
		if _, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "Snapshot"}); err != nil {
			return err
		}
		if _, err := client.GetPrompt(ctx, &mcp.GetPromptParams{Name: "rpa-journey", Arguments: map[string]string{"persona": "qa"}}); err != nil {
			return err
		}
		if _, err := client.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fixture://state"}); err != nil {
			return err
		}
		_, err := client.Complete(ctx, &mcp.CompleteParams{
			Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
			Argument: mcp.CompleteParamsArgument{Name: "persona", Value: "q"},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireProbeMethods(got, "tools/call", "prompts/get", "resources/read", "completion/complete"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCaptured(spec, got); err != nil {
		t.Fatal(err)
	}
	got.Results["tools/call"][0] = json.RawMessage(`{"content":"not-an-array"}`)
	if err := ValidateCaptured(spec, got); err == nil || !strings.Contains(err.Error(), "tools/call") {
		t.Fatalf("invalid tool response was accepted: %v", err)
	}
}

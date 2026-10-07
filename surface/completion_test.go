package surface

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestCompletionValuesAreAlwaysAnArray guards a bug the Go type system cannot
// see: a nil []string marshals to `null`, and `completion.values` must be an
// array. The assertion is against the marshalled bytes rather than the struct.
func TestCompletionValuesAreAlwaysAnArray(t *testing.T) {
	inv := fixtureInventory(t, []string{"all"})
	handler := CompletionHandlerFor(inv, CompletionSources{PersonaIDs: []string{"qa"}})

	cases := map[string]*mcp.CompleteParams{
		"no ref at all":                 {Argument: mcp.CompleteParamsArgument{Name: "persona"}},
		"resource ref is not completed": {Ref: &mcp.CompleteReference{Type: "ref/resource", URI: "x://y"}, Argument: mcp.CompleteParamsArgument{Name: "anything"}},
		"prompt ref, unknown argument":  {Ref: &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"}, Argument: mcp.CompleteParamsArgument{Name: "not-an-argument"}},
		"prefix matches nothing":        {Ref: &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"}, Argument: mcp.CompleteParamsArgument{Name: "persona", Value: "zzz"}},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := handler(context.Background(), &mcp.CompleteRequest{Params: params})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(res)
			if strings.Contains(string(raw), `"values":null`) {
				t.Errorf("values serialized as null: %s", raw)
			}
		})
	}
}

// TestCompletionStillSuggests checks the handler still completes a real prompt
// argument from each source, and never from anything but the configured ones.
func TestCompletionStillSuggests(t *testing.T) {
	inv := fixtureInventory(t, []string{"all"})
	handler := CompletionHandlerFor(inv, CompletionSources{PersonaIDs: []string{"support", "qa"}, CommonApps: []string{"TextEdit"}})
	complete := func(arg, typed string) []string {
		res, err := handler(context.Background(), &mcp.CompleteRequest{Params: &mcp.CompleteParams{
			Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
			Argument: mcp.CompleteParamsArgument{Name: arg, Value: typed},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Completion.Total != len(res.Completion.Values) {
			t.Errorf("total = %d but %d values", res.Completion.Total, len(res.Completion.Values))
		}
		return res.Completion.Values
	}
	if got := complete("persona", ""); strings.Join(got, ",") != "qa,support" {
		t.Errorf("persona completion = %v, want sorted persona IDs", got)
	}
	if got := complete("tool", "S"); strings.Join(got, ",") != "Shell,Snapshot" {
		t.Errorf("tool completion = %v", got)
	}
	if got := complete("app", ""); strings.Join(got, ",") != "TextEdit" {
		t.Errorf("app completion = %v", got)
	}
	if got := complete("toolset", "s"); strings.Join(got, ",") != "screen,shell" {
		t.Errorf("toolset completion = %v", got)
	}
}

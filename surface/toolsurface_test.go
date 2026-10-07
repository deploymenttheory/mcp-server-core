package surface

import (
	"reflect"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"

	"github.com/deploymenttheory/mcp-server-core/inventory"
)

func TestToolsOutsidePersona(t *testing.T) {
	inv := fixtureInventory(t, []string{"screen", "shell"})
	enabled := inv.EnabledToolsets()
	m := fixtureMembership()
	if out := ToolsOutsidePersona([]string{"FileSystem"}, enabled, m); len(out) != 1 || out[0] != "FileSystem" {
		t.Errorf("FileSystem should be flagged, got %v", out)
	}
	if out := ToolsOutsidePersona([]string{"Shell"}, enabled, m); len(out) != 0 {
		t.Errorf("Shell is within the selection and should not be flagged, got %v", out)
	}
	if out := ToolsOutsidePersona([]string{"Kill"}, enabled, m); len(out) != 0 {
		t.Errorf("a tool in no toolset must not be flagged, got %v", out)
	}
}

func TestSplitCredentialExposure(t *testing.T) {
	exp := CredentialExposure{Risky: []string{"shell", "filesystem"}, Perception: []string{"screen"}}
	for _, tc := range []struct {
		name                   string
		enabled                []inventory.ToolsetMetadata
		ack                    policy.StringSet
		unmasked               bool
		wantUnacked, wantAcked []string
	}{
		{"shell unacknowledged refuses", []inventory.ToolsetMetadata{tsScreen, tsShell}, nil, false, []string{"shell"}, nil},
		{"filesystem unacknowledged refuses", []inventory.ToolsetMetadata{tsFiles}, nil, false, []string{"filesystem"}, nil},
		{"shell acknowledged proceeds", []inventory.ToolsetMetadata{tsShell}, policy.StringSet{"shell"}, false, nil, []string{"shell"}},
		{"only shell acked, filesystem still refuses", []inventory.ToolsetMetadata{tsShell, tsFiles}, policy.StringSet{"shell"}, false, []string{"filesystem"}, []string{"shell"}},
		{"no risky toolset served", []inventory.ToolsetMetadata{tsScreen}, nil, false, nil, nil},
		{"unmasked targets widen the set", []inventory.ToolsetMetadata{tsScreen}, nil, true, []string{"screen"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unacked, acked := exp.Split(tc.enabled, tc.ack, tc.unmasked)
			if !reflect.DeepEqual(unacked, tc.wantUnacked) {
				t.Errorf("unacknowledged = %v, want %v", unacked, tc.wantUnacked)
			}
			if !reflect.DeepEqual(acked, tc.wantAcked) {
				t.Errorf("acknowledged = %v, want %v", acked, tc.wantAcked)
			}
		})
	}
}

func TestCredentialsDeclareUnmaskedTargets(t *testing.T) {
	if CredentialsDeclareUnmaskedTargets("", nil) {
		t.Fatal("no file means no declaration")
	}
	if CredentialsDeclareUnmaskedTargets(t.TempDir()+"/missing.json", nil) {
		t.Fatal("an unreadable file reports false and leaves the diagnosis to the loader")
	}
}

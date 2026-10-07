package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/wire"

	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// TestEffectiveConfigEnablesEnforceHTTPS pins the narrowing direction that
// must work: a harness whose composed policy demands HTTPS binds this server's
// URL-shaped tools even when the local config never asked for it.
func TestEffectiveConfigEnablesEnforceHTTPS(t *testing.T) {
	enforce := false
	deps := toolkit.NewBaseDeps(nil, nil)
	ApplyEffectiveConfig(wire.EffectiveConfig{EnforceHTTPS: true}, &enforce, deps, nil, nil, func(string) {}, discardLogger())
	if !deps.EnforceHTTPS() || !enforce {
		t.Fatal("ack's enforce_https did not reach the tool dependencies and the config")
	}
}

// TestEffectiveConfigNeverRelaxes pins the other direction: an ack with the
// protection off must not switch off a protection the local policy set.
func TestEffectiveConfigNeverRelaxes(t *testing.T) {
	enforce := true
	deps := toolkit.NewBaseDeps(nil, nil).WithEnforceHTTPS(true)
	ApplyEffectiveConfig(wire.EffectiveConfig{EnforceHTTPS: false}, &enforce, deps, nil, nil, func(string) {}, discardLogger())
	if !deps.EnforceHTTPS() || !enforce {
		t.Fatal("an ack with enforce_https off relaxed the locally-configured protection")
	}
}

// TestEffectiveConfigAddsProtectedPaths pins that harness-declared paths are
// refused in both directions and that the local protections survive.
func TestEffectiveConfigAddsProtectedPaths(t *testing.T) {
	local := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(local, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	localPaths := GuardrailPaths(GuardrailPathsConfig{CredentialsFile: local}, &policy.Policy{})
	deps := toolkit.NewBaseDeps(nil, nil).WithProtectedPaths(localPaths)

	harnessPath := filepath.Join(t.TempDir(), "harness-audit.jsonl")
	enforce := false
	ApplyEffectiveConfig(wire.EffectiveConfig{ProtectedPaths: []string{harnessPath}},
		&enforce, deps, localPaths, nil, func(string) {}, discardLogger())

	for _, write := range []bool{false, true} {
		if _, denied := deps.ProtectedPathViolation(harnessPath, write); !denied {
			t.Fatalf("harness-declared path not protected (write=%v)", write)
		}
	}
	if _, denied := deps.ProtectedPathViolation(local, false); !denied {
		t.Fatal("extending with harness paths dropped the local credentials-file protection")
	}
}

func TestEffectiveConfigBanner(t *testing.T) {
	var shown []string
	enforce := false
	deps := toolkit.NewBaseDeps(nil, nil)
	record := func(msg string) { shown = append(shown, msg) }
	ApplyEffectiveConfig(wire.EffectiveConfig{}, &enforce, deps, nil, nil, record, discardLogger())
	if len(shown) != 0 {
		t.Fatalf("banner shown without being asked: %q", shown)
	}
	ApplyEffectiveConfig(wire.EffectiveConfig{Banner: true}, &enforce, deps, nil, nil, record, discardLogger())
	if len(shown) != 1 {
		t.Fatalf("banner requested but shown %d times", len(shown))
	}
}

// TestGuardrailPathsCoverGuardrailFiles ports the Windows protected-path table
// onto POSIX paths.
func TestGuardrailPathsCoverGuardrailFiles(t *testing.T) {
	auditDir := t.TempDir() + "/"
	cfg := GuardrailPathsConfig{PolicyConfig: "/etc/mcp/policy.json", CredentialsFile: "/etc/mcp/creds.json"}
	dp := &policy.Policy{Transparency: policy.TransparencyPolicy{AuditDestination: auditDir}}
	deps := toolkit.NewBaseDeps(nil, nil).WithProtectedPaths(GuardrailPaths(cfg, dp))

	for _, tc := range []struct {
		name       string
		path       string
		write      bool
		wantDenied bool
	}{
		{"read credentials denied", "/etc/mcp/creds.json", false, true},
		{"write credentials denied", "/etc/mcp/creds.json", true, true},
		{"read policy allowed", "/etc/mcp/policy.json", false, false},
		{"write policy denied", "/etc/mcp/policy.json", true, true},
		{"read audit allowed", auditDir + "session-x.audit.jsonl", false, false},
		{"write audit file denied", auditDir + "session-x.audit.jsonl", true, true},
		{"read audit key denied", auditDir + AuditKeyFile, false, true},
		{"unrelated file allowed", "/Users/me/Desktop/notes.txt", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, denied := deps.ProtectedPathViolation(tc.path, tc.write); denied != tc.wantDenied {
				t.Errorf("ProtectedPathViolation(%q, write=%v) denied=%v, want %v", tc.path, tc.write, denied, tc.wantDenied)
			}
		})
	}
}

package toolkit

import (
	"path/filepath"
	"testing"
)

func TestProtectedPathCoversTreeAndExact(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator), "var", "mcp", "control")
	tree := NewProtectedPath(nil, dir, "the control dir", true, true, true)
	if !tree.Covers(DefaultNormalizePath(filepath.Join(dir, "kill"))) {
		t.Fatal("a file under a protected tree must be covered")
	}
	if tree.Covers(DefaultNormalizePath(dir + "-other")) {
		t.Fatal("a sibling with the same prefix must not be covered")
	}
	file := NewProtectedPath(nil, filepath.Join(dir, "policy.json"), "the policy", false, false, true)
	if !file.Covers(DefaultNormalizePath(filepath.Join(dir, "policy.json"))) {
		t.Fatal("exact file must be covered")
	}
	if file.Covers(DefaultNormalizePath(filepath.Join(dir, "policy.json", "x"))) {
		t.Fatal("a non-tree path must not cover children")
	}
}

func TestProtectedPathViolationHonoursReadWriteFlags(t *testing.T) {
	policy := filepath.Join(string(filepath.Separator), "etc", "mcp", "policy.json")
	deps := NewBaseDeps(nil, nil).WithProtectedPaths([]ProtectedPath{
		NewProtectedPath(nil, policy, "the policy document", false, false, true),
	})
	if _, v := deps.ProtectedPathViolation(policy, false); v {
		t.Fatal("reading the policy must be allowed")
	}
	reason, v := deps.ProtectedPathViolation(policy, true)
	if !v || reason == "" {
		t.Fatal("writing the policy must be refused with a reason")
	}
	if _, v := deps.ProtectedPathViolation(filepath.Join(string(filepath.Separator), "tmp", "x"), true); v {
		t.Fatal("an unrelated path must not be refused")
	}
}

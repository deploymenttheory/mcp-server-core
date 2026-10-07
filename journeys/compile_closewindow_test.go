package journeys

import "testing"

// TestCloseWindowShortcutIsConfigurable pins the one platform knob in the
// vocabulary: a server that sets CloseWindowShortcut gets its chord in the
// compiled plan, and the default stays the Windows one.
func TestCloseWindowShortcutIsConfigurable(t *testing.T) {
	old := CloseWindowShortcut
	t.Cleanup(func() { CloseWindowShortcut = old })
	if old != "alt+f4" {
		t.Fatalf("default = %q, want alt+f4", old)
	}
	CloseWindowShortcut = "cmd+w"
	steps := closeWindowSteps("close", "Untitled")
	if got := steps[1].Args["shortcut"]; got != "cmd+w" {
		t.Errorf("close step shortcut = %v, want cmd+w", got)
	}
}

package surface

import (
	"github.com/deploymenttheory/mcp-server-core/inventory"
)

// ToolsOutsidePersona returns the --tools entries whose toolset is not among the
// enabled toolsets — the tools served only by the additional-tools bypass. A
// persona is a documented guarantee about the served surface, so widening it with
// --tools is refused; without a persona the operator is composing the surface by
// hand and the bypass is theirs to use. Unknown names (and the always-served
// GuardrailStatus/Kill, which belong to no toolset) are ignored.
//
// membership maps tool name to toolset ID for the server's full manifest.
func ToolsOutsidePersona(tools []string, enabled []inventory.ToolsetMetadata, membership map[string]string) []string {
	enabledSet := make(map[string]bool, len(enabled))
	for _, ts := range enabled {
		enabledSet[string(ts.ID)] = true
	}

	var out []string
	for _, t := range tools {
		ts, ok := membership[t]
		if !ok {
			continue
		}
		if !enabledSet[ts] {
			out = append(out, t)
		}
	}
	return out
}

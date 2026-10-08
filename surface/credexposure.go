package surface

import (
	"encoding/json"
	"os"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"

	"github.com/deploymenttheory/mcp-server-core/inventory"
)

// CredentialExposure names the toolsets that put installed credentials at risk.
//
// Risky toolsets can read an installed credential back out of the calling
// user's credential store, defeating the never-read guarantee: a shell (the
// platform's credential CLI) and a filesystem (a credential-store backup is a
// file). Perception toolsets can read a secret back off the *screen* once it
// has been typed somewhere unmasked: a screenshot returns it as pixels, a text
// read lifts it out of an unmasked control, and the clipboard returns a copied
// selection. They are not risky on their own — injection normally requires a
// destination that reports itself as masked — but a credential declaring
// allow_unmasked_target gives that up, and only then does a perception toolset
// become a credential-disclosure surface.
type CredentialExposure struct {
	Risky      []string
	Perception []string
}

// CredentialsDeclareUnmaskedTargets reports whether any entry in the credentials
// document opts out of the masked-destination check.
//
// It decodes only that flag. The secret fields are deliberately not part of the
// struct, so this runs before startup admission without materialising a
// plaintext — the file's permissions are still checked (checkPerms), and the
// real load (which does decode secrets, into wipeable bytes) happens later and
// only if admitted.
//
// A malformed document is not diagnosed here; it reports false and lets the
// real credentials loader produce the error, so there is one place that decides
// whether a credentials file is valid.
func CredentialsDeclareUnmaskedTargets(path string, checkPerms func(string) error) bool {
	if path == "" {
		return false
	}
	if checkPerms != nil {
		if err := checkPerms(path); err != nil {
			return false
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path, permission-checked above
	if err != nil {
		return false
	}
	var doc struct {
		Credentials []struct {
			AllowUnmaskedTarget bool `json:"allow_unmasked_target"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	for _, c := range doc.Credentials {
		if c.AllowUnmaskedTarget {
			return true
		}
	}
	return false
}

// Toolsets returns the toolsets whose presence puts installed credentials at
// risk, given whether any credential opts out of the masked-destination check.
func (e CredentialExposure) Toolsets(anyUnmaskedTarget bool) []string {
	if !anyUnmaskedTarget {
		return e.Risky
	}
	return append(append([]string{}, e.Risky...), e.Perception...)
}

// Split partitions the risky toolsets that are actually served into those the
// policy acknowledges and those it does not, preserving the canonical order. A
// non-empty unacknowledged list is what forces a startup refusal; the
// acknowledged list is what gets recorded when startup proceeds anyway. The
// order of the two returns matches Risky so the audit record and the error
// message are stable.
func (e CredentialExposure) Split(
	enabled []inventory.ToolsetMetadata,
	ack policy.StringSet,
	anyUnmaskedTarget bool,
) (unacknowledged, acknowledged []string) {
	served := make(map[string]bool, len(enabled))
	for _, ts := range enabled {
		served[string(ts.ID)] = true
	}
	for _, r := range e.Toolsets(anyUnmaskedTarget) {
		if !served[r] {
			continue
		}
		if ack.Contains(r) {
			acknowledged = append(acknowledged, r)
		} else {
			unacknowledged = append(unacknowledged, r)
		}
	}
	return unacknowledged, acknowledged
}

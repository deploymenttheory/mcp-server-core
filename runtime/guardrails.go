// Package runtime is the shared orchestration layer of an MCP server built on
// mcp-server-core: policy loading, the guardrail registry, the receiving
// middleware chain, egress provisioning, the harness servant, the planner, the
// journey runner, evidence sealing and the operator-facing policy operations.
//
// Everything here is platform-agnostic. A server supplies the platform through
// the agentweave-harness interfaces (signals.SystemProbe, signals.HealthProbe,
// contain.SystemActuator, egress.Enforcer) and its own dependency set; the
// server's RunStdio composes the pieces in the order the Windows server pinned.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/export"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// EnvNames derives the names of the secret-carrying environment variables from
// a server's prefix, e.g. "MACOS_MCP_" or "WINDOWS_MCP_".
//
// Secrets are read from the environment rather than from flags or the policy
// document because argv is world-readable and a policy document is meant to be
// reviewable and checked in. This mirrors the credentials invariant — a secret
// may be used, but it is never written somewhere it can be read back.
type EnvNames struct {
	// Prefix is the server's variable prefix, including the trailing underscore.
	Prefix string
}

// AuditKey names the variable holding the audit chain's HMAC key.
func (e EnvNames) AuditKey() string { return e.Prefix + "AUDIT_KEY" }

// ApprovalKey names the variable holding the dual-control signing key.
func (e EnvNames) ApprovalKey() string { return e.Prefix + "APPROVAL_KEY" }

// GraphTenant, GraphClientID and GraphClientSecret name the tier-2 Graph
// credentials.
func (e EnvNames) GraphTenant() string       { return e.Prefix + "GRAPH_TENANT" }
func (e EnvNames) GraphClientID() string     { return e.Prefix + "GRAPH_CLIENT_ID" }
func (e EnvNames) GraphClientSecret() string { return e.Prefix + "GRAPH_CLIENT_SECRET" }

// RemotePolicyToken names the device token for the remote policy decision point.
func (e EnvNames) RemotePolicyToken() string { return e.Prefix + "REMOTE_POLICY_TOKEN" }

// OTLPHeaders names the collector auth headers.
func (e EnvNames) OTLPHeaders() string { return e.Prefix + "OTLP_HEADERS" }

// EvidenceKeyFile names the path to the evidence signing key.
func (e EnvNames) EvidenceKeyFile() string { return e.Prefix + "EVIDENCE_KEY_FILE" }

// Secrets lists every variable holding a secret this server reads once at
// startup, including the export destinations whose names the harness fixes.
//
// A pre-signed URL carries its signature in the query string, so the whole URL
// is a write credential for the evidence bucket — which is why those are listed
// here even though their names are the harness's, not this server's.
func (e EnvNames) Secrets() []string {
	return []string{
		e.AuditKey(),          // forging the audit chain
		e.ApprovalKey(),       // forging a dual-control approval
		e.GraphClientSecret(), // a tenant-wide Entra app secret
		e.RemotePolicyToken(), // impersonating the device to the PDP
		e.OTLPHeaders(),       // collector credentials
		e.EvidenceKeyFile(),   // path to the evidence signing key
		export.EnvSignedURL,
		export.EnvSignedURLManifest,
		export.EnvSignedURLSignature,
	}
}

// LoadPolicy resolves the active device policy.
//
// With no document the embedded default applies: the engine is present, every
// declared signal is evaluated and every verdict recorded, but nothing is
// refused. That is deliberate — an engine that arrived enforcing would start
// refusing tool calls on devices that worked the day before, with no operator
// action and no document to point at.
//
// A named policy that fails to load is fatal. Falling back to the default would
// silently run a device under weaker policy than its operator wrote, which is the
// worst of the available outcomes.
func LoadPolicy(path string, reg *signals.Registry, logger *slog.Logger) (*policy.Policy, error) {
	if path == "" {
		logger.Info("device policy: built-in default (audit only, nothing refused)")
		return policy.Default(), nil
	}
	devicePolicy, err := policy.Load(path, reg.IDs())
	if err != nil {
		return nil, fmt.Errorf("device policy: %w", err)
	}
	logger.Info("device policy loaded",
		"path", path,
		"mode", string(devicePolicy.Mode),
		"signals", devicePolicy.SignalIDs(),
		"rules", len(devicePolicy.Rules),
	)
	return devicePolicy, nil
}

// KillPolicyConfig maps the policy's containment actions to the executor's config.
func KillPolicyConfig(devicePolicy *policy.Policy) contain.KillActionConfig {
	a := devicePolicy.Kill.Actions
	return contain.KillActionConfig{
		Isolate:       a.Isolate,
		KillProcs:     len(a.KillProcs) > 0,
		ProcNames:     a.KillProcs,
		Lock:          a.Lock,
		Shutdown:      a.Shutdown,
		ShutdownDelay: a.ShutdownDelay.Std(),
	}
}

// ToolIndex adapts the served inventory to policy.ToolIndex, so policy rules
// can match on the toolset and annotations a tool actually carries.
//
// It is a snapshot taken once the manifest is assembled, not a live view: the
// manifest cannot change while the process runs — the rug-pull detector trips the
// kill switch if it does — so a snapshot is accurate, and it keeps the lookup a
// map read on the request path rather than a filter pass over every tool.
type ToolIndex map[string]policy.ToolFacts

// Lookup implements policy.ToolIndex.
func (i ToolIndex) Lookup(tool string) (policy.ToolFacts, bool) {
	facts, ok := i[tool]
	return facts, ok
}

// NewToolIndex builds the index from the assembled inventory.
func NewToolIndex(ctx context.Context, inv *inventory.Inventory) ToolIndex {
	tools := inv.AvailableTools(ctx)
	index := make(ToolIndex, len(tools))
	for i := range tools {
		st := &tools[i]
		facts := policy.ToolFacts{
			Name:    st.Tool.Name,
			Toolset: string(st.Toolset.ID),
		}
		// A tool with no annotations is treated as neither read-only nor
		// destructive: it then matches only the broad rules, which is the safe
		// reading of "the manifest does not say".
		if a := st.Tool.Annotations; a != nil {
			facts.ReadOnly = a.ReadOnlyHint
			facts.OpenWorld = a.OpenWorldHint != nil && *a.OpenWorldHint
			facts.Destructive = a.DestructiveHint != nil && *a.DestructiveHint
		}
		index[st.Tool.Name] = facts
	}
	return index
}

// NewGuardrailRegistry builds the signal registry: the tier-1 local checks, the
// just-in-time at-source device-posture checks, and — when the credentials are
// present in the environment — the authoritative tier-2 Graph and remote-policy
// providers.
//
// Registering a signal only makes it available for a policy to declare. Nothing
// here decides whether it is evaluated; that is the policy's job.
func NewGuardrailRegistry(env EnvNames, logger *slog.Logger) *signals.Registry {
	reg := signals.NewRegistry()
	signals.RegisterBuiltins(reg)
	signals.RegisterHealth(reg) // JIT at-source device-posture checks

	gc := signals.GraphConfig{
		TenantID:     os.Getenv(env.GraphTenant()),
		ClientID:     os.Getenv(env.GraphClientID()),
		ClientSecret: os.Getenv(env.GraphClientSecret()),
	}
	if gc.Configured() {
		signals.RegisterGraph(reg, signals.NewGraphClient(gc))
		if logger != nil {
			logger.Info("tier-2 Graph signals available (Entra + Intune compliance)")
		}
	}
	if token := os.Getenv(env.RemotePolicyToken()); token != "" {
		signals.RegisterRemotePolicy(reg, token)
	}
	return reg
}

// TripFunc returns the trip function for one kill trigger. When the trigger is
// armed it is the switch's Trip, which runs the full containment ladder.
// Otherwise it is report-only: the event is still audited and logged, because
// transparency must not be conditional on containment — the operator sees that
// a trigger fired even when they chose not to act on it.
func TripFunc(
	trigger string,
	armed bool,
	kill *contain.KillSwitch,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) func(string) {
	if armed {
		return kill.Trip
	}
	return func(reason string) {
		if auditLog != nil {
			_, _ = auditLog.Append("killswitch.disarmed", map[string]any{
				"trigger": trigger,
				"reason":  reason,
			})
		}
		if logger != nil {
			logger.Warn("kill trigger fired but is disarmed; not containing",
				"trigger", trigger,
				"reason", reason,
				"enable_with", "kill.triggers in the policy document",
			)
		}
	}
}

// DecisionHolder stores the latest decision for the status surface.
type DecisionHolder struct {
	mu sync.Mutex
	d  signals.Decision
}

// Set records the latest decision.
func (h *DecisionHolder) Set(d signals.Decision) { h.mu.Lock(); h.d = d; h.mu.Unlock() }

// Get returns the latest decision.
func (h *DecisionHolder) Get() signals.Decision { h.mu.Lock(); defer h.mu.Unlock(); return h.d }

// GuardrailPathsConfig names the operator-supplied files the file tool must not
// touch, plus the normaliser the server's protected paths are matched with.
type GuardrailPathsConfig struct {
	CredentialsFile string
	PolicyConfig    string
	Normalize       toolkit.PathNormalizer
}

// GuardrailPaths lists the guardrail files the file tool must not touch: the
// credentials file (no read — a read is plaintext into the model's context — and
// no write), the audit log (no write), and the policy document (no write).
// Reading the audit log or the policy is allowed; both are meant to be inspected.
func GuardrailPaths(cfg GuardrailPathsConfig, p *policy.Policy) []toolkit.ProtectedPath {
	n := cfg.Normalize
	var out []toolkit.ProtectedPath
	if cfg.CredentialsFile != "" {
		out = append(out, toolkit.NewProtectedPath(n, cfg.CredentialsFile, "the credentials file", false, true, true))
	}
	if cfg.PolicyConfig != "" {
		out = append(out, toolkit.NewProtectedPath(n, cfg.PolicyConfig, "the policy document", false, false, true))
	}
	if p == nil {
		return out
	}
	if dest := p.Transparency.AuditDestination; dest != "" && dest != "stderr" {
		out = append(out, toolkit.NewProtectedPath(n, dest, "the audit log", AuditDestinationIsDir(dest), false, true))
		// The audit key: no read and no write. Reading it is enough to forge a
		// chain that verifies, which is the whole thing the key exists to prevent
		// — unlike the log itself, which is meant to be inspected.
		if dir := AuditKeyDir(dest); dir != "" {
			out = append(out, toolkit.NewProtectedPath(n,
				filepath.Join(dir, AuditKeyFile), "the audit signing key", false, true, true))
		}
	}
	// The kill-switch control directory: no write, because a file placed here is
	// the sentinel trigger and writing one is an attempt to actuate the
	// containment ladder — an escalation the agent must never reach. No read
	// either: the directory is the operator's channel to the server, not the
	// agent's to inspect.
	//
	// This is one of two defences. It only binds the file tool, and the shell
	// toolset reaches the same path with no such check, which is why the
	// sentinel also has to carry a token the agent cannot know (see SentinelToken).
	if dir := p.InFlight.ControlDir; dir != "" {
		out = append(out, toolkit.NewProtectedPath(n, dir, "the kill-switch control directory", true, true, true))
	}
	return out
}

// AuditDestinationIsDir mirrors the audit package's directory detection: an
// explicit trailing separator, or an existing directory. A directory destination
// protects every session file and the manifest under it.
func AuditDestinationIsDir(dest string) bool {
	if strings.HasSuffix(dest, "/") || strings.HasSuffix(dest, `\`) {
		return true
	}
	info, err := os.Stat(dest)
	return err == nil && info.IsDir()
}

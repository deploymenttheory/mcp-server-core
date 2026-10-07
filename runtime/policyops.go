package runtime

import (
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
)

// The operator-facing operations behind the `policy` subcommands. They exist so
// the three questions an operator actually asks — is this document valid, what
// does this device look like right now, and why was that call refused — can each
// be answered without starting a server.

// ValidatePolicy loads and validates a policy document against the signals the
// registry knows.
//
// It touches no device: validation is about the document and the set of signals
// this build can evaluate, so it runs anywhere, including in CI on a machine
// with no secure enclave and no domain.
func ValidatePolicy(path string, reg *signals.Registry) (*policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	devicePolicy, err := policy.Load(path, reg.IDs())
	if err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return devicePolicy, nil
}

// EvaluatePolicy reads every signal the policy declares and returns the decision
// for the startup scope.
//
// Every signal is read live, cache bypassed: an operator running this wants the
// device as it is now, and a cached answer would be answering a question nobody
// asked. That makes it slow — seconds, on a device where every probe has to
// run — which is correct for a diagnostic and is exactly why the request path
// does not work this way.
//
// envFn builds the evaluation environment over the server's platform probes.
func EvaluatePolicy(
	ctx context.Context,
	devicePolicy *policy.Policy,
	reg *signals.Registry,
	envFn func() *signals.Env,
) signals.Decision {
	engine := policy.NewEngine(devicePolicy, reg, nil, envFn)
	engine.ReadAll(ctx)
	probe := envFn().Sys
	verdict := engine.Evaluate(ctx, policy.StartupSubject())
	return engine.DecisionFrom(verdict, probe.DeviceIdentity(), probe.RunContext())
}

// PolicyCoverage is what covers one tool, for `policy explain`.
type PolicyCoverage struct {
	Tool string `json:"tool"`
	// Known reports whether the tool is in the served manifest. A rule can still
	// cover an unknown tool through a toolset "*" match, and saying so is the
	// point: an operator who mistyped a name should see that, not an empty result
	// that reads like "nothing applies".
	Known   bool                 `json:"known"`
	Facts   policy.ToolFacts     `json:"facts"`
	Rules   []PolicyCoverageRule `json:"rules"`
	Signals []string             `json:"required_signals"`
}

// PolicyCoverageRule is one rule that covers the tool.
type PolicyCoverageRule struct {
	Name     string   `json:"name"`
	Requires []string `json:"requires"`
	OnFail   string   `json:"on_fail"`
}

// ExplainPolicy reports which rules cover a tool and what they require.
//
// It evaluates nothing: an operator asking why a call was refused should not
// have to run device probes, and should be able to ask on a machine that is not
// the one that refused it. index is the served manifest's tool index.
func ExplainPolicy(devicePolicy *policy.Policy, reg *signals.Registry, index ToolIndex, tool string) PolicyCoverage {
	engine := policy.NewEngine(devicePolicy, reg, index, nil)

	facts, known := index.Lookup(tool)
	cov := PolicyCoverage{Tool: tool, Known: known, Facts: facts}

	required := map[string]bool{}
	for _, r := range engine.Explain(engine.SubjectForTool("tools/call", tool)) {
		cov.Rules = append(cov.Rules, PolicyCoverageRule{
			Name:     ruleDisplayName(r, len(cov.Rules)),
			Requires: r.Require,
			OnFail:   r.OnFail.String(),
		})
		for _, id := range r.Require {
			required[id] = true
		}
	}
	for id := range required {
		cov.Signals = append(cov.Signals, id)
	}
	sort.Strings(cov.Signals)
	return cov
}

// ruleDisplayName falls back to a positional label for an unnamed rule. Naming
// rules is worth the keystrokes precisely so this fallback is never what an
// operator reads during an incident.
func ruleDisplayName(r policy.Rule, index int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", index)
}

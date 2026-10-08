package runtime

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// TestKillPolicyConfigMapsContainment checks the policy's containment actions
// reach the executor, and that a policy configuring none produces none.
func TestKillPolicyConfigMapsContainment(t *testing.T) {
	none := KillPolicyConfig(&policy.Policy{})
	if none.Isolate || none.Lock || none.Shutdown || none.KillProcs {
		t.Errorf("a policy with no actions must contain nothing, got %+v", none)
	}

	full := KillPolicyConfig(&policy.Policy{Kill: policy.KillPolicy{
		Actions: policy.KillActions{
			Isolate:   true,
			Lock:      true,
			KillProcs: []string{"evil"},
		},
	}})
	if !full.Isolate || !full.Lock || !full.KillProcs || full.Shutdown {
		t.Errorf("containment actions did not map through: %+v", full)
	}
	if len(full.ProcNames) != 1 || full.ProcNames[0] != "evil" {
		t.Errorf("process names did not map through: %+v", full.ProcNames)
	}
}

// capturingDest records audit entries so the disarmed path can be inspected.
type capturingDest struct{ entries []audit.AuditEntry }

func (s *capturingDest) Write(e audit.AuditEntry) error {
	s.entries = append(s.entries, e)
	return nil
}
func (s *capturingDest) Flush() error { return nil }
func (s *capturingDest) Close() error { return nil }

func TestTripFuncArmedTripsTheSwitch(t *testing.T) {
	var reason string
	kill := contain.NewKillSwitch(func(r string) { reason = r })
	dest := &capturingDest{}

	trip := TripFunc("rugpull", true, kill, audit.NewAuditLog(dest), nil)
	trip("manifest drift")

	if tripped, _ := kill.Tripped(); !tripped {
		t.Error("armed trigger must trip the kill switch")
	}
	if reason != "manifest drift" {
		t.Errorf("trip reason = %q, want the caller's reason", reason)
	}
}

// TestTripFuncDisarmedAuditsWithoutContaining is the transparency guarantee: a
// disarmed trigger still lands in the hash-chained audit log (so the operator can
// see it fired) while containing nothing.
func TestTripFuncDisarmedAuditsWithoutContaining(t *testing.T) {
	var tripped bool
	kill := contain.NewKillSwitch(func(string) { tripped = true })
	dest := &capturingDest{}

	trip := TripFunc("posture-drift", false, kill, audit.NewAuditLog(dest), nil)
	trip("secure-boot=fail")

	if tripped {
		t.Error("disarmed trigger must not contain")
	}
	if got, _ := kill.Tripped(); got {
		t.Error("disarmed trigger must leave the kill switch untripped")
	}
	if len(dest.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(dest.entries))
	}
	e := dest.entries[0]
	if e.Event != "killswitch.disarmed" {
		t.Errorf("event = %q, want killswitch.disarmed", e.Event)
	}
	payload := string(e.Payload)
	for _, want := range []string{"posture-drift", "secure-boot=fail"} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload missing %q: %s", want, payload)
		}
	}
	if err := audit.VerifyChain(dest.entries); err != nil {
		t.Errorf("disarmed entries must keep the chain verifiable: %v", err)
	}
}

// TestTripFuncNilAuditIsSafe covers the tests-and-degraded path where no audit
// log is wired.
func TestTripFuncNilAuditIsSafe(t *testing.T) {
	kill := contain.NewKillSwitch(nil)
	TripFunc("sentinel", false, kill, nil, nil)("no audit configured")
	if tripped, _ := kill.Tripped(); tripped {
		t.Error("disarmed trigger must not trip even without an audit log")
	}
}

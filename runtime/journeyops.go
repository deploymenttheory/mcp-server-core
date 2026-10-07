package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"

	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/journeys"
	"github.com/deploymenttheory/mcp-server-core/runrecord"
	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// JourneyReport is the outcome of running one journey.
type JourneyReport struct {
	Name      string `json:"name"`
	PlanID    string `json:"plan_id"`
	Passed    bool   `json:"passed"`
	Completed int    `json:"completed"`
	Failed    int    `json:"failed"`
	Skipped   int    `json:"skipped"`
	// Report is the human-readable per-step apply log.
	Report string `json:"report"`
	// Manifest is the change manifest the plan adjudicated to before running.
	Manifest string `json:"manifest,omitempty"`
	// RunRecord is where the run's OTLP/JSON trace was written, when an evidence
	// directory is configured.
	RunRecord string `json:"run_record,omitempty"`
	// Evidence lists the images the run captured.
	Evidence []string `json:"evidence,omitempty"`
	// MissingEvidence lists expected_evidence labels the run did not produce. A
	// non-empty list fails the run even when every assertion passed.
	MissingEvidence []string `json:"missing_evidence,omitempty"`
}

// JourneyRun is everything a journey needs from the server that is running it.
// The server stands up the platform engine, the policy engine and the served
// inventory exactly as a session would; this type carries them in.
type JourneyRun struct {
	// Engine is the policy engine with its tool index already set.
	Engine *policy.Engine
	// Inventory is the served manifest. It must include the testing toolset.
	Inventory *inventory.Inventory
	// Deps is the server's dependency set. It must implement toolkit.EvidenceSink
	// and toolkit.ReadRegister (toolkit.BaseDeps does) and must have the
	// evidence directory wired, or captures are not persisted.
	Deps any
	// EvidenceSink and ReadRegister are the two optional capabilities the run
	// reads off Deps; the server passes the same object when it has them.
	EvidenceSink toolkit.EvidenceSink
	ReadRegister toolkit.ReadRegister
	// Planner hook: the run wires its planner into Deps through this, so the
	// Plan/Apply tools (if served) and the run share one. May be nil.
	SetPlanner func(toolkit.Planner)
	// AuditLog is the session's chain.
	AuditLog *audit.AuditLog
	// SessionStamp ties the run's audit chain and evidence together.
	SessionStamp string
	// EvidenceRoot is transparency.evidence_dir; "" disables persistence.
	EvidenceRoot string
	// ServiceName and Version identify the server in the run record.
	ServiceName string
	Version     string
	Logger      *slog.Logger
}

// RunJourney compiles a journey document to a plan and executes it against the
// live platform, through the same planner Apply uses: every step is
// policy-evaluated, audited as plan.step, and fail-stopped on the first failure.
// A failed assertion is an Assert/WaitFor tool error — a failed step — so the
// run stops and reports it, which is what makes a journey a test.
//
// raw is the journey document as written; name is used in error messages.
func RunJourney(ctx context.Context, raw []byte, name string, run JourneyRun) (JourneyReport, error) {
	j, err := journeys.Parse(raw)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("journey %s: %w", name, err)
	}
	if err := j.Validate(); err != nil {
		return JourneyReport{}, fmt.Errorf("journey %s: %w", name, err)
	}
	logger := run.Logger
	if logger == nil {
		logger = slog.Default()
	}

	runner := InventoryRegistry{Inv: run.Inventory, Deps: run.Deps}

	doc, origins, err := journeys.CompileWithOrigins(j, run.SessionStamp)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("compile journey: %w", err)
	}

	// A run is a trace. The recorder is separate from the OTLP exporter on
	// purpose: telemetry.sample_ratio governs what is exported, and must not
	// govern what is recorded — a run record holding a statistical subset of its
	// own steps is not evidence.
	host, _ := os.Hostname()
	rec := runrecord.New(runrecord.Options{
		ServiceName: run.ServiceName, ServiceVersion: run.Version,
		SessionID: run.SessionStamp, HostName: host,
	})
	runStarted := time.Now()
	runSpan, closeRun := rec.Open(runrecord.Span{
		Name:  "journey " + j.Name,
		Start: runStarted,
		Attrs: []runrecord.Attr{
			runrecord.String("journey.name", j.Name),
			runrecord.Int("journey.version", int64(j.Version)),
			runrecord.String("journey.document.sha256", documentDigest(raw)),
			runrecord.String("journey.plan.id", doc.PlanID),
			runrecord.String("journey.session.id", run.SessionStamp),
			runrecord.Int("journey.steps.total", int64(len(doc.Steps))),
		},
	})
	tracer := NewJourneyTracer(rec, origins, run.Deps, runSpan)

	sessionPlanner := NewPlanner(run.Engine, run.AuditLog, runner, nil).
		WithReadRegister(run.ReadRegister).
		WithStepObserver(tracer.ObserveStep)
	if run.SetPlanner != nil {
		run.SetPlanner(sessionPlanner)
	}
	rawPlan, err := json.Marshal(doc)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("marshal compiled journey: %w", err)
	}

	_, _ = run.AuditLog.Append("journey.started", map[string]any{
		"name": j.Name, "steps": len(doc.Steps), "session": run.SessionStamp,
	})

	prop, err := sessionPlanner.Propose(ctx, rawPlan)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("compile journey to a plan: %w", err)
	}
	if !prop.Allowed {
		reason := fmt.Sprintf("blocked by device policy before running (%s)", prop.Severity)
		closeRun(time.Now(), true, reason, runrecord.Bool("journey.passed", false))
		_, _ = run.AuditLog.Append(
			"journey.finished",
			map[string]any{"name": j.Name, "passed": false, "reason": "blocked by policy"},
		)
		report := JourneyReport{
			Name: j.Name, PlanID: prop.PlanID, Passed: false, Failed: len(doc.Steps),
			Report: reason, Manifest: prop.Manifest,
		}
		report.RunRecord = persistRunRecord(run.EvidenceRoot, j.Name, run.SessionStamp, rec, logger)
		return report, nil
	}

	app, err := sessionPlanner.Apply(ctx, prop.PlanID)
	if err != nil {
		return JourneyReport{}, fmt.Errorf("run journey: %w", err)
	}

	// Expected evidence is checked against the run, not against the document. The
	// static check at validate time only says some step claims it will capture the
	// label — which a run that fail-stopped at step 2 satisfies without ever having
	// produced it.
	var artifacts []toolkit.EvidenceArtifact
	if run.EvidenceSink != nil {
		artifacts = run.EvidenceSink.CapturedEvidence()
	}
	captured, missing := ReconcileEvidence(j.ExpectedEvidence, artifacts)

	passed := app.Failed == 0 && app.Skipped == 0 &&
		app.Completed == len(doc.Steps) && len(missing) == 0
	report := app.Report
	if len(missing) > 0 {
		report += fmt.Sprintf("  expected evidence never captured: %s\n", strings.Join(missing, ", "))
	}

	closeRun(time.Now(), !passed, JourneyStatusMessage(passed, app.Failed, missing),
		runrecord.Bool("journey.passed", passed),
		runrecord.Int("journey.steps.completed", int64(app.Completed)),
		runrecord.Int("journey.steps.failed", int64(app.Failed)),
		runrecord.Int("journey.steps.skipped", int64(app.Skipped)),
	)

	_, _ = run.AuditLog.Append("journey.finished", map[string]any{
		"name": j.Name, "passed": passed,
		"completed": app.Completed, "failed": app.Failed, "skipped": app.Skipped,
		"evidence": captured, "missing_evidence": missing,
	})

	return JourneyReport{
		Name: j.Name, PlanID: app.PlanID, Passed: passed,
		Completed: app.Completed, Failed: app.Failed, Skipped: app.Skipped,
		Report: report, Manifest: prop.Manifest,
		RunRecord:       persistRunRecord(run.EvidenceRoot, j.Name, run.SessionStamp, rec, logger),
		Evidence:        captured,
		MissingEvidence: missing,
	}, nil
}

// ReconcileEvidence compares what the journey said a passing run must produce
// against what it actually captured.
func ReconcileEvidence(expected []string, artifacts []toolkit.EvidenceArtifact) (captured, missing []string) {
	seen := map[string]bool{}
	for _, a := range artifacts {
		seen[a.Label] = true
		captured = append(captured, a.Label)
	}
	for _, want := range expected {
		if !seen[want] {
			missing = append(missing, want)
		}
	}
	return captured, missing
}

// JourneyStatusMessage renders the run span's status description.
func JourneyStatusMessage(passed bool, failed int, missing []string) string {
	switch {
	case passed:
		return "passed"
	case failed > 0:
		return fmt.Sprintf("%d step(s) failed", failed)
	case len(missing) > 0:
		return "expected evidence never captured: " + strings.Join(missing, ", ")
	default:
		return "did not complete"
	}
}

// persistRunRecord writes the trace, logging rather than failing on error: the
// journey's verdict is already on the audit chain, and losing the richer record
// is not a reason to report a passing suite as broken.
func persistRunRecord(root, name, session string, rec *runrecord.Recorder, logger *slog.Logger) string {
	path, err := WriteRunRecord(EvidenceSubdir(root, "journeys"), name, session, rec)
	if err != nil {
		logger.Error("journey run record not written", "error", err)
		return ""
	}
	return path
}

// EvidenceSubdir returns a subdirectory of the evidence root, or "" when no
// evidence directory is configured — which disables persistence rather than
// failing, since a missing output directory is a configuration choice.
func EvidenceSubdir(root, sub string) string {
	if root == "" {
		return ""
	}
	return filepath.Join(root, sub)
}

// WithToolset adds id to a toolset selection. A nil selection means "the default
// set", so it is made explicit as "default" plus id rather than collapsing to id
// alone, which would silently drop every default toolset.
func WithToolset(toolsets []string, id string) []string {
	if len(toolsets) == 0 {
		return []string{"default", id}
	}
	for _, t := range toolsets {
		if t == id || t == "all" {
			return toolsets
		}
	}
	return append(append([]string(nil), toolsets...), id)
}

// documentDigest is the SHA-256 of the journey document as written. It is the
// stable identity of what ran: trace ids differ between runs of the same file,
// and this does not.
func documentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

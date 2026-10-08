package runtime

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/status"
	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
)

// SnapshotFn builds the always-on server-status snapshot provider.
func SnapshotFn(
	startedAt time.Time,
	rp *watch.RugPull,
	hb *watch.Heartbeat,
	auditLog *audit.AuditLog,
	kill *contain.KillSwitch,
	egressSvc *egress.Service,
	egressCfg policy.EgressPolicy,
	exportSt *status.ExportStatus,
) status.SnapshotProvider {
	return func() status.ServerStatus {
		beats, age := hb.Snapshot()
		seq, head := auditLog.Head()
		tripped, reason := kill.Tripped()
		return status.ServerStatus{
			UptimeSec:        time.Since(startedAt).Seconds(),
			ToolManifestHash: rp.Baseline(),
			HeartbeatSeq:     beats,
			HeartbeatAgeSec:  age.Seconds(),
			AuditSeq:         seq,
			AuditChainHead:   head,
			Killed:           tripped,
			KillReason:       reason,
			Egress:           EgressStatus(egressSvc, egressCfg),
			EvidenceExport:   exportSt,
		}
	}
}

// NewLogger returns a structured logger writing to logFile (debug level) or, if
// empty, to stderr (info level). stdout is never used, so it stays clean for
// the MCP stdio transport.
func NewLogger(logFile string) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stderr
	level := slog.LevelInfo
	cleanup := func() {}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // operator-chosen log path
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file %q: %w", logFile, err)
		}
		w = f
		level = slog.LevelDebug
		cleanup = func() { _ = f.Close() }
	}

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	return logger, cleanup, nil
}

// SessionStamp mints the one stamp a session's audit file, recording and
// evidence bundle correlate by name.
func SessionStamp() string { return time.Now().Format("20060102-150405") }

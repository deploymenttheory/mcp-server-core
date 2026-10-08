package runtime

import (
	"log/slog"
	"os"

	"github.com/deploymenttheory/agentweave-harness/wire"

	"github.com/deploymenttheory/mcp-server-core/toolkit"
)

// ApplyEffectiveConfig folds the hello.ack's effective config into this
// session's settings. The wire contract requires the config to be applied
// before the server builds its tool surface, and the call site sits between
// the handshake and RegisterAll so the tools this session serves are bound by
// it from the first call.
//
// Narrowing only: the harness can enable a protection this server did not
// configure — enforce HTTPS, additional protected paths — but never relax one
// the local policy already set. A harness that could switch local protections
// off would be a way around the document the operator reviewed.
//
// enforceHTTPS is the server's config field, mutated as well as deps because the
// guardrail Env closes over it, so the may-run endpoint gets the same answer
// the URL-shaped tools do. localPaths are the protections the server derived
// itself; they survive the extension.
//
// Harness-declared protected paths deny both read and write. The wire carries
// only the paths, not why they are protected, and the server cannot tell a
// tamper-target (write must be refused) from a secret (read must be refused),
// so it refuses both rather than guess.
//
// The announced egress proxy (port and executable) is consumed by the egress
// provisioning, which the server feeds directly — see HarnessEgress.
func ApplyEffectiveConfig(
	ec wire.EffectiveConfig,
	enforceHTTPS *bool,
	deps *toolkit.BaseDeps,
	localPaths []toolkit.ProtectedPath,
	normalize toolkit.PathNormalizer,
	banner func(string),
	logger *slog.Logger,
) {
	if ec.EnforceHTTPS && !*enforceHTTPS {
		*enforceHTTPS = true
		deps.WithEnforceHTTPS(true)
		logger.Info("enforce HTTPS enabled by the harness effective config")
	}
	if len(ec.ProtectedPaths) > 0 {
		all := append([]toolkit.ProtectedPath(nil), localPaths...)
		for _, p := range ec.ProtectedPaths {
			all = append(all, toolkit.NewProtectedPath(
				normalize, p, "protected by the harness policy", statIsDir(p), true, true))
		}
		deps.WithProtectedPaths(all)
		logger.Info("protected paths extended by the harness effective config",
			"count", len(ec.ProtectedPaths))
	}
	if ec.Banner && banner != nil {
		banner("This session is governed by agentweave-harness")
	}
}

// statIsDir reports whether the path names an existing directory, so a
// harness-protected directory shields its whole tree. A path that does not
// exist yet is protected as a single file — creating it is a write, which is
// already refused.
func statIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

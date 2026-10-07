package runtime

import (
	"log/slog"
	"os"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// ScrubSecretEnv removes the startup secrets from this process's environment,
// once every component that needs them holds its own copy.
//
// It is the second of two defences, and it exists because the first cannot be
// complete. The server's process runner withholds every prefixed variable when
// it builds a child environment — but any future code path that spawns a
// process without going through it would inherit the parent environment as it
// stands. Clearing the values here means there is nothing left to inherit,
// whatever route a child is started by.
//
// It also covers the two variables the prefix rule cannot know about: the egress
// proxy's shared secret and the status endpoint's bearer token are named *by the
// policy document*, so their variables can be called anything at all.
//
// Order matters. Call this only after the audit log, the approvals client, the
// signal registry, the telemetry exporter and the egress proxy have been
// constructed; each reads its secret exactly once, at startup, into the struct
// that uses it.
func ScrubSecretEnv(env EnvNames, devicePolicy *policy.Policy, logger *slog.Logger) {
	secrets := env.Secrets()
	names := make([]string, 0, len(secrets)+2)
	names = append(names, secrets...)
	if devicePolicy != nil && devicePolicy.Egress.AuthTokenEnv != "" {
		names = append(names, devicePolicy.Egress.AuthTokenEnv)
	}
	// The status token reaches POST /revoke, which runs the containment ladder —
	// so it is at least as worth clearing as the proxy credential beside it.
	if devicePolicy != nil && devicePolicy.Transparency.StatusTokenEnv != "" {
		names = append(names, devicePolicy.Transparency.StatusTokenEnv)
	}

	cleared := 0
	for _, name := range names {
		if _, present := os.LookupEnv(name); !present {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			// Not fatal: the process runner still withholds the prefix from
			// children, so this is defence in depth failing back to one layer
			// rather than none. Say so plainly instead of failing startup.
			if logger != nil {
				logger.Warn("could not clear a secret from the environment; "+
					"it remains readable by any process started outside the process runner",
					"variable", name, "error", err)
			}
			continue
		}
		cleared++
	}
	if cleared > 0 && logger != nil {
		logger.Debug("cleared startup secrets from the process environment", "count", cleared)
	}
}

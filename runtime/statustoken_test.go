package runtime

import (
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// TestStatusTokenPrefersTheEnvironment pins the direction of the fix: the
// credential that reaches POST /revoke, and through it the containment ladder,
// should not have to live in a document the agent can read.
func TestStatusTokenPrefersTheEnvironment(t *testing.T) {
	t.Setenv("TEST_MCP_STATUS_TOKEN", "from-the-environment")

	got, err := ResolveStatusToken(policy.TransparencyPolicy{
		StatusAddr:     "127.0.0.1:8181",
		StatusToken:    "from-the-document",
		StatusTokenEnv: "TEST_MCP_STATUS_TOKEN",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-the-environment" {
		t.Errorf("status_token_env must win over the inline value, got %q", got)
	}
}

// TestStatusTokenEnvNamingNothingIsFatal: a status endpoint serving without the
// credential the document asked for is a weaker posture than the document
// describes, and /revoke sits behind it. Same answer as the egress proxy's.
func TestStatusTokenEnvNamingNothingIsFatal(t *testing.T) {
	_, err := ResolveStatusToken(policy.TransparencyPolicy{
		StatusAddr:     "127.0.0.1:8181",
		StatusTokenEnv: "TEST_MCP_STATUS_TOKEN_UNSET",
	}, nil)
	if err == nil {
		t.Fatal("an env-named status token that holds nothing must refuse startup")
	}
	if !strings.Contains(err.Error(), "revoke") {
		t.Errorf("the error should say what is behind the endpoint, got: %v", err)
	}
}

// TestStatusTokenInlineStillWorks: removing the key would break documents that run
// today, and unknown keys are rejected outright, so the inline form is deprecated
// and warned about rather than dropped.
func TestStatusTokenInlineStillWorks(t *testing.T) {
	got, err := ResolveStatusToken(policy.TransparencyPolicy{
		StatusAddr:  "127.0.0.1:8181",
		StatusToken: "from-the-document",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-the-document" {
		t.Errorf("the inline token must still be honoured, got %q", got)
	}
}

// TestStatusTokenEnvIsScrubbed: the variable is named by the policy document, so
// the prefix rule in the process runner cannot know about it -- the
// same gap scrubSecretEnv already covers for the egress proxy's credential.
func TestStatusTokenEnvIsScrubbed(t *testing.T) {
	t.Setenv("TEST_MCP_STATUS_TOKEN", "secret")

	p := &policy.Policy{}
	p.Transparency.StatusTokenEnv = "TEST_MCP_STATUS_TOKEN"
	ScrubSecretEnv(EnvNames{Prefix: "TEST_MCP_"}, p, nil)

	if v, present := os.LookupEnv("TEST_MCP_STATUS_TOKEN"); present {
		t.Errorf("the status token must be cleared from the environment, still holds %q", v)
	}
}

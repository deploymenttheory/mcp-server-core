package surface

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/mcpspec"
)

// recordingMiddleware appends name to order when a request passes through it.
// refuse makes it answer without calling next, standing in for a policy denial.
func recordingMiddleware(mu *sync.Mutex, order *[]string, name string, refuse bool) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				mu.Lock()
				*order = append(*order, name)
				mu.Unlock()
			}
			if refuse && method == "tools/list" {
				return nil, errors.New("refused by policy")
			}
			return next(ctx, method, req)
		}
	}
}

// listOnce runs one tools/list against the server, ignoring whether it succeeded
// — a refused call is the interesting case.
func listOnce(t *testing.T, server *mcp.Server) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "order-test", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	_, _ = cs.ListTools(ctx, nil)
}

// TestReceivingMiddlewareRunsOutermostFirst pins the order InstallReceiving
// produces. It is a regression test for a real inversion: the layers were added
// one AddReceivingMiddleware call at a time, and because each call wraps the
// chain built so far, the LAST middleware added became the outermost. The policy
// engine ended up outside the audit layer.
func TestReceivingMiddlewareRunsOutermostFirst(t *testing.T) {
	var mu sync.Mutex
	var order []string

	s, _, _ := newFixtureSurface(t, []string{"all"},
		recordingMiddleware(&mu, &order, "audit", false),
		recordingMiddleware(&mu, &order, "rugpull", false),
		recordingMiddleware(&mu, &order, "enforce", false),
	)
	listOnce(t, s.Server)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"audit", "rugpull", "enforce"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("middleware order = %v, want %v", order, want)
	}
}

// TestOuterMiddlewareObservesRefusedRequests is the property the ordering exists
// for. The audit layer must record a call the policy engine refuses — those
// refusals are exactly what an investigator needs, and the inverted chain
// dropped them: no tool.call entry was ever written for a denied call.
func TestOuterMiddlewareObservesRefusedRequests(t *testing.T) {
	var mu sync.Mutex
	var order []string

	s, _, _ := newFixtureSurface(t, []string{"all"},
		recordingMiddleware(&mu, &order, "audit", false),
		recordingMiddleware(&mu, &order, "enforce", true), // refuses, never calls next
	)
	listOnce(t, s.Server)

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "audit" || order[1] != "enforce" {
		t.Fatalf("audit did not observe the refused request: order = %v", order)
	}
}

// TestCacheHintsDescribeThisServer checks the SEP-2549 caching hints on the wire.
//
// The SDK defaults every cacheable result to cacheScope "public" with ttlMs 0.
// That is structurally conformant but untrue: "public" invites a shared
// intermediary to cache one caller's answer and serve it to another, and a
// server's manifest depends on the persona and toolsets the session was started
// with. The values are set deliberately; this test is what stops an SDK upgrade
// silently restoring the defaults.
func TestCacheHintsDescribeThisServer(t *testing.T) {
	got := captureFixture(t, []string{"all"})
	for name, payload := range map[string]json.RawMessage{"tools/list": got.ToolsListResult, "handshake": got.HandshakeResult} {
		t.Run(name, func(t *testing.T) {
			if len(payload) == 0 {
				t.Skip("nothing captured for this revision")
			}
			var env struct {
				TTLMs      *int    `json:"ttlMs"`
				CacheScope *string `json:"cacheScope"`
			}
			if err := json.Unmarshal(payload, &env); err != nil {
				t.Fatal(err)
			}
			if env.TTLMs == nil || env.CacheScope == nil {
				t.Fatalf("%s must carry both ttlMs and cacheScope: %s", name, payload)
			}
			if *env.CacheScope != cacheScopePrivate {
				t.Errorf("cacheScope = %q, want %q", *env.CacheScope, cacheScopePrivate)
			}
			if want := int(manifestTTL.Milliseconds()); *env.TTLMs != want {
				t.Errorf("ttlMs = %d, want %d", *env.TTLMs, want)
			}
		})
	}
}

// TestGuardrailToolsAlwaysServed pins that the two guardrail tools are part of
// the captured manifest, as they are in a served session.
func TestGuardrailToolsAlwaysServed(t *testing.T) {
	got := captureFixture(t, []string{"screen"})
	served := string(got.ToolsListResult)
	for _, name := range []string{"GuardrailStatus", "Kill", "Snapshot"} {
		if !strings.Contains(served, `"`+name+`"`) {
			t.Errorf("%s must be in tools/list", name)
		}
	}
	if strings.Contains(served, `"Shell"`) {
		t.Error("a toolset outside the selection must not be served")
	}
}

// TestToolsListOrderIsDeterministic pins the SHOULD that protocol 2026-07-28
// added: servers should return tools/list in a deterministic order, so clients
// can cache the manifest and so an LLM prompt built from it hits the prompt cache.
func TestToolsListOrderIsDeterministic(t *testing.T) {
	names := func() []string {
		got := captureFixture(t, []string{"all"})
		var payload struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(got.ToolsListResult, &payload); err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(payload.Tools))
		for i, tool := range payload.Tools {
			out[i] = tool.Name
		}
		return out
	}
	first := names()
	if len(first) == 0 {
		t.Fatal("no tools served")
	}
	for i := 0; i < 3; i++ {
		if next := names(); strings.Join(next, ",") != strings.Join(first, ",") {
			t.Fatalf("tools/list order is not deterministic: %v vs %v", first, next)
		}
	}
}

func schemaDir() string { return filepath.Join("..", "schema") }

// TestServedSurfaceValidatesAgainstTheNewestRevision is the offline pre-flight:
// every wire object the surface serves validates against the newest vendored
// schema, so `go test` still catches a broken schema on a machine with no Node.
func TestServedSurfaceValidatesAgainstTheNewestRevision(t *testing.T) {
	m, err := mcpspec.LoadManifest(schemaDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(schemaDir(), m.Newest())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFixture(t, []string{"all"})
	if got.NegotiatedVersion != m.Newest() {
		t.Errorf("session negotiated %q but the newest vendored revision is %q", got.NegotiatedVersion, m.Newest())
	}
	if err := spec.ValidateJSON("ListToolsResult", got.ToolsListResult); err != nil {
		t.Errorf("tools/list result does not validate: %v", err)
	}
	for _, result := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"ListPromptsResult", got.PromptsListResult},
		{"ListResourcesResult", got.ResourcesListResult},
		{"ListResourceTemplatesResult", got.ResourceTemplatesListResult},
	} {
		if err := spec.ValidateJSON(result.name, result.raw); err != nil {
			t.Errorf("%s does not validate: %v", result.name, err)
		}
	}
	if err := spec.ValidateJSON("ServerCapabilities", got.Capabilities); err != nil {
		t.Errorf("server capabilities do not validate: %v", err)
	}
	def, ok := spec.FirstPresent("DiscoverResult", "InitializeResult")
	if !ok {
		t.Skipf("revision %s defines neither handshake result", m.Newest())
	}
	if err := spec.ValidateJSON(def, got.HandshakeResult); err != nil {
		t.Errorf("handshake does not validate against %s: %v\ncaptured: %s", def, err, got.HandshakeResult)
	}
}

// TestCaptureRecordsTheWireNotTheSDKView guards against reporting the handshake
// from ClientSession.InitializeResult(), a synthesized legacy view on
// 2026-07-28 that omits the fields DiscoverResult requires.
func TestCaptureRecordsTheWireNotTheSDKView(t *testing.T) {
	got := captureFixture(t, []string{"all"})
	var hs map[string]json.RawMessage
	if err := json.Unmarshal(got.HandshakeResult, &hs); err != nil {
		t.Fatal(err)
	}
	if _, isDiscover := hs["supportedVersions"]; !isDiscover {
		t.Skip("this revision negotiates initialize, not server/discover")
	}
	for _, field := range []string{"resultType", "cacheScope", "ttlMs", "supportedVersions"} {
		if _, ok := hs[field]; !ok {
			t.Errorf("captured handshake is missing %q", field)
		}
	}
	for method, raw := range map[string]json.RawMessage{
		"tools/list":               got.ToolsListResult,
		"prompts/list":             got.PromptsListResult,
		"resources/list":           got.ResourcesListResult,
		"resources/templates/list": got.ResourceTemplatesListResult,
	} {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Errorf("%s: decode raw result: %v", method, err)
			continue
		}
		if _, ok := result["resultType"]; !ok {
			t.Errorf("%s: raw result lacks resultType", method)
		}
	}
}

// TestPinnedCapabilitiesNeverAdvertiseListChanged keeps the manifest static:
// listChanged re-opens the silent re-advertisement channel rug-pull detection
// exists to close.
func TestPinnedCapabilitiesNeverAdvertiseListChanged(t *testing.T) {
	c := PinnedCapabilities()
	if c.Tools.ListChanged || c.Prompts.ListChanged || c.Resources.ListChanged {
		t.Fatal("pinned capabilities must not advertise listChanged")
	}
	if c.Logging != nil || c.Extensions != nil {
		t.Fatal("logging (deprecated) and extensions (none implemented) must stay unset")
	}
}

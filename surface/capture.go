package surface

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/guardrails/status"

	"github.com/deploymenttheory/mcp-server-core/inventory"
)

// captureTimeout bounds the in-process session so a capture can never hang CI.
const captureTimeout = 30 * time.Second

// Captured is what a client actually receives from a server, as raw wire JSON.
//
// Everything here is bytes off a real session rather than a re-marshalling of
// Go types, because the divergence worth catching lives exactly there: between
// a project's hand-written tool schemas, the SDK's serialization, and the
// published spec.
//
// The authority on conformance is the official suite, run against the loopback
// HTTP host. This capture serves two narrower purposes: a fast offline pass/fail
// check against the vendored schemas, so `go test` means something on a machine
// without Node; and the reference side of the equivalence test that lets evidence
// gathered over HTTP transfer to the shipped stdio binary.
type Captured struct {
	// ToolsListResult is the tools/list result as served.
	ToolsListResult json.RawMessage
	// These lists are captured from the server's raw replies, before the client
	// SDK can normalize or discard fields.
	PromptsListResult           json.RawMessage
	ResourcesListResult         json.RawMessage
	ResourceTemplatesListResult json.RawMessage
	// Results contains every successful raw reply, grouped by request method.
	// Optional probes can add tools/call, prompts/get, resources/read and
	// completion/complete replies without changing production registration.
	Results map[string][]json.RawMessage
	// HandshakeResult is the server/discover result (or, before 2026-07-28, the
	// initialize result) as served.
	HandshakeResult json.RawMessage
	// Capabilities is the serverCapabilities object as served.
	Capabilities json.RawMessage
	// NegotiatedVersion is the protocol revision the session settled on.
	NegotiatedVersion string
}

// Protocol method names used for wire-frame lookup.
//
// The 2026-07-28 handshake is server/discover; initialize is retained because a
// pre-2026-07-28 client still negotiates with it, and the capture has to find
// whichever one the session actually used.
const (
	MethodDiscover   = "server/discover"
	MethodInitialize = "initialize"
)

// Capture runs a real in-process MCP session against a built surface over an
// in-memory transport and returns the wire objects a client actually receives.
//
// The surface must already have had InstallReceiving called (with no guardrail
// layers — the capture exists to record the advertised surface offline). The
// two always-served guardrail tools are registered here with inert handlers so
// they are part of the scored manifest, exactly as a served session has them.
//
// tools/list never invokes a tool handler, so the dependency set the surface
// was built with may carry a nil engine; a handler call here would be a bug,
// not a supported path.
func Capture(ctx context.Context, s *Surface, inv *inventory.Inventory, deps any, clientVersion string) (Captured, error) {
	return CaptureWithProbes(ctx, s, inv, deps, clientVersion, nil)
}

// ProbeFunc makes safe, product-specific MCP calls over the same session used
// for capture. Callers choose arguments that cannot actuate the desktop in CI.
type ProbeFunc func(context.Context, *mcp.ClientSession) error

// CaptureWithProbes captures the advertised surface and optional method replies
// from the real registered handlers over an in-memory MCP session.
func CaptureWithProbes(ctx context.Context, s *Surface, inv *inventory.Inventory, deps any, clientVersion string, probe ProbeFunc) (Captured, error) {
	var in Captured
	server := s.Server
	inv.RegisterAll(ctx, server, deps)

	kill := contain.NewKillSwitch(nil)
	statusTool, statusHandler := status.StatusTool(
		func() signals.Decision { return signals.Decision{} },
		func() status.ServerStatus { return status.ServerStatus{} },
		kill,
	)
	server.AddTool(statusTool, statusHandler)
	killTool, killHandler := status.KillTool(func(string) {})
	server.AddTool(killTool, killHandler)

	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()

	serverTransport, rawClientTransport := mcp.NewInMemoryTransports()
	// Record the client side of the wire so the handshake can be validated as the
	// server actually sent it, not as the SDK normalizes it for legacy callers.
	frames := NewFrameLog()
	clientTransport := &RecordingTransport{Inner: rawClientTransport, Frames: frames}

	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		return in, fmt.Errorf("connect server: %w", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "spec-check", Version: clientVersion}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return in, fmt.Errorf("connect client: %w", err)
	}
	defer func() { _ = cs.Close() }()

	initResult := cs.InitializeResult()
	if initResult == nil {
		return in, fmt.Errorf("no initialize result captured") //nolint:err113 // local sentinel not needed
	}

	_, err = cs.ListTools(ctx, nil)
	if err != nil {
		return in, fmt.Errorf("list tools: %w", err)
	}
	if _, err := cs.ListPrompts(ctx, nil); err != nil {
		return in, fmt.Errorf("list prompts: %w", err)
	}
	if _, err := cs.ListResources(ctx, nil); err != nil {
		return in, fmt.Errorf("list resources: %w", err)
	}
	if _, err := cs.ListResourceTemplates(ctx, nil); err != nil {
		return in, fmt.Errorf("list resource templates: %w", err)
	}
	if probe != nil {
		if err := probe(ctx, cs); err != nil {
			return in, fmt.Errorf("probe server methods: %w", err)
		}
	}

	// Prefer the recorded wire result. On 2026-07-28 the handshake is
	// server/discover, whose result carries resultType/cacheScope/ttlMs/
	// supportedVersions; ClientSession.InitializeResult() is a synthesized legacy
	// view without them, so validating it would misreport the server. Fall back to
	// the synthesized view only for older revisions that really do use initialize.
	if raw, ok := frames.ResultFor(MethodDiscover); ok {
		in.HandshakeResult = raw
	} else if raw, ok := frames.ResultFor(MethodInitialize); ok {
		in.HandshakeResult = raw
	} else if in.HandshakeResult, err = json.Marshal(initResult); err != nil {
		return in, fmt.Errorf("marshal handshake result: %w", err)
	}
	var handshake struct {
		Capabilities json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(in.HandshakeResult, &handshake); err != nil {
		return in, fmt.Errorf("decode handshake capabilities: %w", err)
	}
	if len(handshake.Capabilities) == 0 {
		return in, fmt.Errorf("handshake did not advertise capabilities")
	}
	in.Capabilities = handshake.Capabilities
	for _, result := range []struct {
		method string
		out    *json.RawMessage
	}{
		{"tools/list", &in.ToolsListResult},
		{"prompts/list", &in.PromptsListResult},
		{"resources/list", &in.ResourcesListResult},
		{"resources/templates/list", &in.ResourceTemplatesListResult},
	} {
		raw, ok := frames.ResultFor(result.method)
		if !ok {
			return in, fmt.Errorf("no raw %s result captured", result.method)
		}
		*result.out = raw
	}
	in.Results = frames.ResultsByMethod()

	in.NegotiatedVersion = initResult.ProtocolVersion
	return in, nil
}

// CaptureRawResults runs safe probes against a server whose handlers the caller
// registers, returning the replies after the SDK has applied wire decoration.
// It is useful for OS-backed result constructors that cannot invoke a desktop
// action on CI but still need to prove their emitted protocol shape.
func CaptureRawResults(ctx context.Context, server *mcp.Server, probe ProbeFunc) (map[string][]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	frames := NewFrameLog()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect server: %w", err)
	}
	defer func() { _ = ss.Close() }()
	client := mcp.NewClient(&mcp.Implementation{Name: "spec-check", Version: "test"}, nil)
	cs, err := client.Connect(ctx, &RecordingTransport{Inner: clientTransport, Frames: frames}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect client: %w", err)
	}
	defer func() { _ = cs.Close() }()
	if err := probe(ctx, cs); err != nil {
		return nil, fmt.Errorf("probe server: %w", err)
	}
	return frames.ResultsByMethod(), nil
}

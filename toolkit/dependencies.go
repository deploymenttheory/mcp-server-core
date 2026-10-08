// Package toolkit holds the platform-agnostic building blocks an MCP server
// built on mcp-server-core shares: argument coercion, result constructors, the
// assertion algebra, protected-path guards, the evidence sink, the planner
// contract and the dependency-injection plumbing that puts a server's
// dependencies on the request context.
//
// Tool handlers retrieve their dependencies from the request context (injected
// once at startup, or per request for an HTTP transport) via
// InjectDepsMiddleware and MustDepsFromContext, mirroring github-mcp-server's
// dependency-injection design. The dependency type is a server-specific
// interface — it embeds ToolDependencies and adds whatever platform engine the
// server drives — which is why the accessors are generic.
package toolkit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
)

// depsContextKey is the private context key under which dependencies are
// stored. A private type prevents collisions with other packages.
type depsContextKey struct{}

// ErrDepsNotInContext is returned/panicked when dependencies are missing from
// the context.
var ErrDepsNotInContext = errors.New("tool dependencies not found in context; use ContextWithDeps to inject")

// ToolDependencies is the platform-agnostic surface every server's dependency
// set provides. A server declares its own interface embedding this one and
// adding its engine accessor, so handlers written against the server's type
// still satisfy everything the shared runtime needs.
type ToolDependencies interface {
	// Logger returns the structured logger, optionally enriched with
	// request-scoped fields from ctx.
	Logger(ctx context.Context) *slog.Logger

	// IsFeatureEnabled reports whether a named feature flag is enabled.
	IsFeatureEnabled(ctx context.Context, flagName string) bool

	// Credentials returns the non-secret registry of credentials installed at
	// init: names, targets, usernames, and classes. It deliberately cannot expose
	// a secret — the plaintext never leaves the platform engine, so no tool
	// handler is able to return one.
	Credentials() []CredentialInfo

	// EnforceHTTPS reports whether the Enforce HTTPS setting is on. Tools that
	// fetch or navigate to a URL must refuse plaintext http:// when it is.
	EnforceHTTPS() bool

	// EgressProxy returns the loopback egress proxy address ("host:port") this
	// session's outbound HTTP must route through, or "" when no proxy is
	// provisioned. Tools that fetch a URL honor it, so the server's own
	// reaching-out is governed by the same allowlist as everything else's.
	EgressProxy() string
}

// CredentialInfo describes an installed credential without its secret. It is
// what the Credentials tool lists and what completion offers; there is no field
// that could carry a value, by construction.
type CredentialInfo struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Username string `json:"username,omitempty"`
	Type     string `json:"type"`
	Persist  string `json:"persist"`
	Present  bool   `json:"present"`
	// Injectable is false for credential classes the platform store will not
	// read back.
	Injectable bool `json:"injectable"`
	// AllowUnmaskedTarget lets this credential be injected into a control that
	// does not report itself as masked. It defaults to false, so injection
	// normally requires a confirmed password field. It is an operator decision,
	// declared per credential in the credentials document, because it trades the
	// never-read guarantee for reach into destinations that cannot report
	// themselves as secure text fields.
	AllowUnmaskedTarget bool `json:"allow_unmasked_target"`
}

// PathNormalizer renders a path in the one form protected-path matching
// compares, so the same file cannot be reached under a different spelling.
// Each platform supplies its own: the spellings a filesystem folds together
// are a property of that filesystem.
type PathNormalizer func(path string) string

// DefaultNormalizePath is the platform-neutral normaliser: trimmed, cleaned and
// lower-cased. Servers on case-sensitive filesystems may still use it — it is
// merely over-protective there — but a server with platform aliases (extended
// prefixes, data streams, /private folds) must supply its own.
func DefaultNormalizePath(path string) string {
	return strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
}

// ProtectedPath marks a filesystem location a file tool must not touch, so the
// agent cannot use it to reach the guardrail state that governs it — read the
// credentials file back, or write over the audit log or the policy document.
// It is a guardrail, not a sandbox: matching is by normalised path, so a hard
// link still reaches the file under another name.
type ProtectedPath struct {
	path      string // normalised path
	label     string // human name for the refusal message
	tree      bool   // protect everything under path (a directory), not just path
	denyRead  bool
	denyWrite bool
}

// NewProtectedPath builds a ProtectedPath, normalising the path for matching.
func NewProtectedPath(normalize PathNormalizer, path, label string, tree, denyRead, denyWrite bool) ProtectedPath {
	if normalize == nil {
		normalize = DefaultNormalizePath
	}
	return ProtectedPath{
		path:      normalize(path),
		label:     label,
		tree:      tree,
		denyRead:  denyRead,
		denyWrite: denyWrite,
	}
}

// Label is the human name used in refusal messages.
func (p ProtectedPath) Label() string { return p.label }

// Covers reports whether target (already normalised) falls under this
// protected path: exact match, or anywhere below it when it protects a tree.
func (p ProtectedPath) Covers(target string) bool {
	if p.tree {
		return target == p.path || strings.HasPrefix(target, p.path+string(filepath.Separator))
	}
	return target == p.path
}

// ReadRegister is the optional interface a dependency set implements to carry
// the run-scoped result register: what the most recent read returned, which a
// result.text assertion compares against.
//
// It is an optional interface rather than a method on ToolDependencies for the
// reason ProtectedPathViolation is: adding to the interface would break every
// other implementation, including the fakes the tool tests are built on.
//
// The register is supplied to an assertion as *environment*. It is deliberately
// never spliced into the assertion's arguments: a plan runs verbatim from the
// stored, approved document and its argument digest is what the audit chain
// records, so rewriting arguments at execution time would break both.
type ReadRegister interface {
	LastRead() (string, bool)
	SetLastRead(text string)
}

// AssertionRecord is what an assertion actually did: the comparison it made and
// the value it read. It exists so a run record can carry the observed value —
// the thing a text log never carried, and the difference between knowing a test
// broke and knowing why.
type AssertionRecord struct {
	Subject  string
	Operator string
	Expected string
	Observed string
	Passed   bool
	// Polls is how many times the condition was evaluated: 1 when not waited. A
	// step that passed on its fifteenth poll of a fifteen-second budget is a
	// different fact from one that passed immediately, and it is the one that
	// predicts a suite about to become flaky.
	Polls   int
	Timeout float64
}

// AssertionRegister is the optional interface a dependency set implements to
// carry the most recent assertion's outcome.
//
// It is a side channel rather than something on the tool result on purpose: the
// alternative is putting it in the result's structured content or _meta, which
// would change the Assert tool's wire output and put it under the protocol's
// schema obligations, for information the model already has in the text.
type AssertionRegister interface {
	RecordAssertion(AssertionRecord)
	LastAssertion() (AssertionRecord, bool)
}

// ProtectedPathChecker is the optional interface a dependency set implements
// when it carries protected paths. File tools check for it.
type ProtectedPathChecker interface {
	ProtectedPathViolation(absPath string, write bool) (reason string, violated bool)
}

// BaseDeps is the platform-agnostic half of a server's dependency set. A
// server embeds it (by pointer) in its own struct, adds the platform engine, and
// gets every shared capability — the registers, the evidence sink, the planner
// hook, the protected paths — for free.
type BaseDeps struct {
	logger         *slog.Logger
	featureChecker inventory.FeatureFlagChecker
	credentials    []CredentialInfo
	enforceHTTPS   bool
	egressProxy    string
	protectedPaths []ProtectedPath
	normalizePath  PathNormalizer
	planner        Planner
	evidence       *evidenceWriter

	readMu   sync.Mutex
	lastRead string
	hasRead  bool

	assertMu   sync.Mutex
	lastAssert AssertionRecord
	hasAssert  bool
}

// Compile-time assertions on the optional interfaces BaseDeps carries.
var (
	_ ToolDependencies     = (*BaseDeps)(nil)
	_ ReadRegister         = (*BaseDeps)(nil)
	_ AssertionRegister    = (*BaseDeps)(nil)
	_ EvidenceSink         = (*BaseDeps)(nil)
	_ PlannerProvider      = (*BaseDeps)(nil)
	_ ProtectedPathChecker = (*BaseDeps)(nil)
)

// NewBaseDeps constructs a BaseDeps.
func NewBaseDeps(logger *slog.Logger, featureChecker inventory.FeatureFlagChecker) *BaseDeps {
	if logger == nil {
		logger = slog.Default()
	}
	return &BaseDeps{logger: logger, featureChecker: featureChecker, normalizePath: DefaultNormalizePath}
}

// RecordAssertion implements AssertionRegister.
func (d *BaseDeps) RecordAssertion(r AssertionRecord) {
	d.assertMu.Lock()
	defer d.assertMu.Unlock()
	d.lastAssert, d.hasAssert = r, true
}

// LastAssertion implements AssertionRegister.
func (d *BaseDeps) LastAssertion() (AssertionRecord, bool) {
	d.assertMu.Lock()
	defer d.assertMu.Unlock()
	return d.lastAssert, d.hasAssert
}

// LastRead implements ReadRegister.
func (d *BaseDeps) LastRead() (string, bool) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	return d.lastRead, d.hasRead
}

// SetLastRead implements ReadRegister, recording what a read step returned.
func (d *BaseDeps) SetLastRead(text string) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	d.lastRead, d.hasRead = text, true
}

// WithCredentials records the credentials installed at init, so the Credentials
// tool can list what is available. Returns the receiver for chaining.
func (d *BaseDeps) WithCredentials(creds []CredentialInfo) *BaseDeps {
	d.credentials = creds
	return d
}

// WithEnforceHTTPS turns the Enforce HTTPS setting on for tools that reach a URL.
// Returns the receiver for chaining.
func (d *BaseDeps) WithEnforceHTTPS(on bool) *BaseDeps {
	d.enforceHTTPS = on
	return d
}

// WithEgressProxy records the loopback egress proxy address outbound HTTP must
// route through. Returns the receiver for chaining.
func (d *BaseDeps) WithEgressProxy(addr string) *BaseDeps {
	d.egressProxy = addr
	return d
}

// WithPathNormalizer sets the normaliser ProtectedPathViolation applies to the
// path it is asked about. It must be the same one the protected paths were
// built with. Returns the receiver for chaining.
func (d *BaseDeps) WithPathNormalizer(n PathNormalizer) *BaseDeps {
	if n != nil {
		d.normalizePath = n
	}
	return d
}

// WithProtectedPaths records the guardrail paths the file tool must not touch.
// Returns the receiver for chaining.
func (d *BaseDeps) WithProtectedPaths(paths []ProtectedPath) *BaseDeps {
	d.protectedPaths = paths
	return d
}

// WithPlanner wires the plan-and-apply engine, so the Plan and Apply tools can
// reach it. Returns the receiver for chaining.
func (d *BaseDeps) WithPlanner(p Planner) *BaseDeps {
	d.planner = p
	return d
}

// Planner implements PlannerProvider. It returns nil when plan-and-apply is not
// wired, which the Plan/Apply tools treat as "planning not available".
func (d *BaseDeps) Planner() Planner { return d.planner }

// ProtectedPathViolation reports whether accessing absPath (for write when write
// is true, otherwise read) would touch a protected guardrail path, and a reason
// suitable for a tool error. It implements ProtectedPathChecker.
func (d *BaseDeps) ProtectedPathViolation(absPath string, write bool) (string, bool) {
	target := d.normalizePath(absPath)
	verb := "read"
	if write {
		verb = "written"
	}
	for _, p := range d.protectedPaths {
		if !p.Covers(target) {
			continue
		}
		if (write && p.denyWrite) || (!write && p.denyRead) {
			return fmt.Sprintf("%s cannot be %s via the file tool: it is %s, a guardrail path",
				absPath, verb, p.label), true
		}
	}
	return "", false
}

// Credentials implements ToolDependencies.
func (d *BaseDeps) Credentials() []CredentialInfo { return d.credentials }

// EnforceHTTPS implements ToolDependencies.
func (d *BaseDeps) EnforceHTTPS() bool { return d.enforceHTTPS }

// EgressProxy implements ToolDependencies.
func (d *BaseDeps) EgressProxy() string { return d.egressProxy }

// Logger implements ToolDependencies.
func (d *BaseDeps) Logger(_ context.Context) *slog.Logger { return d.logger }

// IsFeatureEnabled implements ToolDependencies.
func (d *BaseDeps) IsFeatureEnabled(ctx context.Context, flagName string) bool {
	if d.featureChecker == nil || flagName == "" {
		return false
	}
	enabled, err := d.featureChecker(ctx, flagName)
	if err != nil {
		d.logger.Warn("feature flag check failed", "flag", flagName, "error", err)
		return false
	}
	return enabled
}

// InjectDepsMiddleware returns MCP receiving middleware that injects the given
// dependencies into the context of every request, so tool handlers can read
// them via MustDepsFromContext instead of capturing them in closures.
func InjectDepsMiddleware(deps any) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			return next(ContextWithDeps(ctx, deps), method, req)
		}
	}
}

// ContextWithDeps returns a copy of ctx carrying the given dependencies.
func ContextWithDeps(ctx context.Context, deps any) context.Context {
	return context.WithValue(ctx, depsContextKey{}, deps)
}

// DepsFromContext retrieves the dependencies from ctx as D, reporting whether
// they were present and of that type.
func DepsFromContext[D any](ctx context.Context) (D, bool) {
	deps, ok := ctx.Value(depsContextKey{}).(D)
	return deps, ok
}

// MustDepsFromContext retrieves the dependencies from ctx as D, panicking if
// absent. Use it in handlers where dependencies are required.
func MustDepsFromContext[D any](ctx context.Context) D {
	deps, ok := DepsFromContext[D](ctx)
	if !ok {
		panic(ErrDepsNotInContext)
	}
	return deps
}

// NewTool creates a ServerTool whose typed handler receives dependencies pulled
// from the request context. This avoids allocating a closure per tool at
// registration time. Ensure InjectDepsMiddleware is installed so deps are
// present when handlers run.
func NewTool[D any, In any, Out any](
	toolset inventory.ToolsetMetadata,
	tool mcp.Tool,
	handler func(ctx context.Context, deps D, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error),
) inventory.ServerTool {
	return inventory.NewServerToolWithContextHandler(tool, toolset,
		func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error) {
			return handler(ctx, MustDepsFromContext[D](ctx), req, args)
		})
}

// NewToolFromHandler creates a ServerTool from a raw handler that receives
// dependencies from context. Use it when the handler needs the raw request
// rather than typed, pre-unmarshaled arguments.
func NewToolFromHandler[D any](
	toolset inventory.ToolsetMetadata,
	tool mcp.Tool,
	handler func(ctx context.Context, deps D, req *mcp.CallToolRequest) (*mcp.CallToolResult, error),
) inventory.ServerTool {
	return inventory.NewServerTool(tool, toolset, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handler(ctx, MustDepsFromContext[D](ctx), req)
	})
}

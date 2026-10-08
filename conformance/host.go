// Package conformance holds what the official MCP conformance suite
// (github.com/modelcontextprotocol/conformance) needs from a server under
// test and nothing a released binary should carry: the suite's named fixture
// tools, resources and prompts, a loopback-only Streamable HTTP host, and a
// recovering middleware so one broken handler cannot cost the evidence for
// every scenario after it.
//
// Nothing here is platform-specific. A server imports this package only from
// files behind its own `conformance` build tag, which is what keeps the HTTP
// listener out of the product build.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
)

// shutdownGrace bounds the wait for in-flight requests when the context ends,
// so a hung stream cannot leave a CI job running to its timeout.
const shutdownGrace = 5 * time.Second

// ErrNotLoopback reports a listen address that is not loopback.
var ErrNotLoopback = errors.New("conformance host refuses to bind: loopback only")

// RequireLoopback refuses any address that is not loopback.
//
// The host has no authentication and no authorization: it is a test fixture
// that serves the full tool manifest of a desktop-automation server. Binding
// it to a routable interface would publish that manifest, and the ability to
// call it, to the network. The check is here rather than in a CLI so no
// future caller can route around it.
func RequireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNotLoopback, addr)
	}
	return nil
}

// Serve exposes server over Streamable HTTP at addr+path until ctx ends.
//
// The bound URL is printed to stdout, which is the runner's contract: with an
// ephemeral port the address is only known here and the suite needs it for
// --url. Logs go to the logger (stderr by convention) so stdout stays clean.
//
// The transport is stateless: protocol 2026-07-28 removed protocol-level
// sessions, and the suite's stateless scenarios exercise exactly that.
// DNS-rebinding protection is left at its default (on); the suite has a
// scenario for it because a localhost server without HTTPS or auth is the
// case that needs it.
func Serve(ctx context.Context, server *mcp.Server, addr, path string, logger *slog.Logger) error {
	if err := RequireLoopback(addr); err != nil {
		return err
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, Logger: logger})

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	url := fmt.Sprintf("http://%s%s", listener.Addr().String(), path)
	fmt.Fprintln(os.Stdout, url)
	logger.Info("conformance host listening", "url", url, "stateless", true)

	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- httpServer.Serve(listener) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		// Deliberately not derived from ctx: a cancelled context makes
		// Shutdown abandon in-flight requests immediately, and the grace
		// period is the point — the suite's last response should finish.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck // see above
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// RecoverMiddleware turns a panicking handler into a JSON-RPC error instead
// of a dead process.
//
// It belongs on the conformance host and not on a production server. Here
// the whole point is to finish the run and produce results, so one broken
// handler must not cost the evidence for every scenario after it: a run
// whose failures might mean "the server is not there" proves nothing. A
// production session makes the opposite trade, because a panic there means
// the engine's state is unknown.
func RecoverMiddleware(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("handler panicked", "method", method, "panic", r,
						"stack", string(debug.Stack()))
					res = nil
					err = &jsonrpc.Error{
						Code:    jsonrpc.CodeInternalError,
						Message: fmt.Sprintf("handler for %s panicked: %v", method, r),
					}
				}
			}()
			return next(ctx, method, req)
		}
	}
}

// Probe satisfies signals.SystemProbe without a desktop engine.
//
// The conformance host drives no real desktop, so the default policy's
// signals have nothing to read. Every method returns a zero value, which
// makes run-context report a non-interactive session and therefore fail.
// Under the default policy that is a warning and nothing more: the
// middleware is exercised on every request, and no request is refused.
type Probe struct{}

func (*Probe) RunShell(context.Context, string) (string, error) { return "", nil }
func (*Probe) DomainSKU() (signals.DomainSKU, error)            { return signals.DomainSKU{}, nil }
func (*Probe) RunContext() signals.RunContext                   { return signals.RunContext{} }
func (*Probe) DeviceIdentity() signals.DeviceIdentity {
	return signals.DeviceIdentity{Hostname: "conformance-host"}
}
func (*Probe) IsAdmin() bool { return false }

// AuditDestination writes the hash-chained audit entries to the logger, so a
// conformance run leaves the same transparency trail a real session would
// and the entries land in the workflow log next to the suite's output.
type AuditDestination struct{ Logger *slog.Logger }

func (s *AuditDestination) Write(e audit.AuditEntry) error {
	s.Logger.Info("audit", "seq", e.Seq, "event", e.Event, "hash", e.EntryHash)
	return nil
}
func (*AuditDestination) Flush() error { return nil }
func (*AuditDestination) Close() error { return nil }

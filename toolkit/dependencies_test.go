package toolkit

import (
	"context"
	"testing"
)

type testDeps interface {
	ToolDependencies
	Engine() string
}

type fakeDeps struct {
	*BaseDeps
}

func (f fakeDeps) Engine() string { return "fake" }

func TestGenericDepsRoundTrip(t *testing.T) {
	ctx := ContextWithDeps(context.Background(), fakeDeps{NewBaseDeps(nil, nil)})
	d := MustDepsFromContext[testDeps](ctx)
	if d.Engine() != "fake" {
		t.Fatal("wrong deps")
	}
	if _, ok := DepsFromContext[testDeps](context.Background()); ok {
		t.Fatal("empty context must report absent")
	}
	if _, ok := DepsFromContext[string](ctx); ok {
		t.Fatal("wrong type must report absent")
	}
}

func TestMustDepsPanicsWhenAbsent(t *testing.T) {
	defer func() {
		if r := recover(); r != ErrDepsNotInContext {
			t.Fatalf("want ErrDepsNotInContext panic, got %v", r)
		}
	}()
	MustDepsFromContext[testDeps](context.Background())
}

package toolkit

import (
	"errors"
	"net/url"
	"testing"
)

func TestEnforceHTTPSSchemeIsCaseInsensitiveAndMatchable(t *testing.T) {
	u, _ := url.Parse("HTTP://example.com/path")
	err := EnforceHTTPSScheme(u, true)
	if !errors.Is(err, ErrPlaintextHTTP) {
		t.Fatalf("want ErrPlaintextHTTP, got %v", err)
	}
	if err := EnforceHTTPSScheme(u, false); err != nil {
		t.Fatalf("gate off must allow: %v", err)
	}
	s, _ := url.Parse("https://example.com")
	if err := EnforceHTTPSScheme(s, true); err != nil {
		t.Fatalf("https must pass: %v", err)
	}
}

func TestURLSchemeIfURLRequiresExplicitScheme(t *testing.T) {
	for in, want := range map[string]string{
		"textedit":           "",
		"example.com":        "",
		"http://example.com": "http",
		"HTTPS://x":          "https",
		"ftp://x":            "",
	} {
		got, ok := URLSchemeIfURL(in)
		if (want != "") != ok || got != want {
			t.Errorf("%q: got (%q,%v) want %q", in, got, ok, want)
		}
	}
}

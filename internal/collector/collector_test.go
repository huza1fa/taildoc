package collector

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeTag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"prod", "tag:prod"},
		{"tag:prod", "tag:prod"},
	}
	for _, c := range cases {
		if got := normalizeTag(c.in); got != c.want {
			t.Errorf("normalizeTag(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeLegacyPort(t *testing.T) {
	cases := []struct {
		port, proto, want string
	}{
		{"5432", "", "tcp:5432"},
		{"5432", "tcp", "tcp:5432"},
		{"53", "udp", "udp:53"},
		{"22", "icmp", "icmp:22"},
	}
	for _, c := range cases {
		if got := normalizeLegacyPort(c.port, c.proto); got != c.want {
			t.Errorf("normalizeLegacyPort(%q, %q) = %q, want %q", c.port, c.proto, got, c.want)
		}
	}
}

func TestCollectRequiresToken(t *testing.T) {
	t.Setenv("TS_ACCESS_TOKEN", "")
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if _, err := Collect(context.Background()); err == nil {
		t.Fatal("expected error when TS_ACCESS_TOKEN is unset")
	} else if !strings.Contains(err.Error(), "TS_ACCESS_TOKEN") {
		t.Errorf("error should mention TS_ACCESS_TOKEN, got: %v", err)
	}
}

func TestCollectUnauthenticatedHintsAuthLogin(t *testing.T) {
	t.Setenv("TS_ACCESS_TOKEN", "")
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	_, err := Collect(context.Background())
	if err == nil {
		t.Fatal("expected error when no credentials are available")
	}
	if !strings.Contains(err.Error(), "auth login") {
		t.Errorf("error should hint at `taildoc auth login`, got: %v", err)
	}
}

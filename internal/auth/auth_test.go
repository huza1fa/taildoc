package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"tailscale.com/client/tailscale/v2"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taildoc", "config.json")

	in := &Credentials{
		Method:       MethodOAuth,
		ClientID:     "k1234567890abcdef",
		ClientSecret: "shhh",
		Tailnet:      "example.com",
	}
	if err := Save(in, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("file perms = %o, want 600", perm)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out == nil {
		t.Fatal("Load returned nil")
	}
	if *out != *in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestSaveDirPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "config.json")
	if err := Save(&Credentials{Method: MethodAPIKey, APIKey: "k"}, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 && runtime.GOOS != "windows" {
		t.Errorf("dir perms = %o, want 700", perm)
	}
}

func TestLoadMissingFile(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if c != nil {
		t.Errorf("expected nil credentials, got %+v", c)
	}
}

func TestResolveEnvPrecedence(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("TAILDOC_CONFIG", configPath)
	t.Setenv("TS_ACCESS_TOKEN", "env-token")

	// Also write a config file to prove env wins.
	cfg := &Credentials{Method: MethodAPIKey, APIKey: "file-token"}
	if err := Save(cfg, configPath); err != nil {
		t.Fatal(err)
	}

	creds, source, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if source != "env" {
		t.Errorf("source = %q, want \"env\"", source)
	}
	if creds == nil || creds.APIKey != "env-token" {
		t.Errorf("expected env token to win, got %+v", creds)
	}
	if creds.Method != MethodAPIKey {
		t.Errorf("method = %q, want apikey", creds.Method)
	}
}

func TestResolveConfigFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("TAILDOC_CONFIG", configPath)
	os.Unsetenv("TS_ACCESS_TOKEN")

	cfg := &Credentials{Method: MethodOAuth, ClientID: "kid", ClientSecret: "sec"}
	if err := Save(cfg, configPath); err != nil {
		t.Fatal(err)
	}

	creds, source, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if source != configPath {
		t.Errorf("source = %q, want %q", source, configPath)
	}
	if creds == nil || creds.Method != MethodOAuth {
		t.Errorf("expected oauth creds from file, got %+v", creds)
	}
}

func TestResolveNone(t *testing.T) {
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	os.Unsetenv("TS_ACCESS_TOKEN")

	creds, source, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds != nil {
		t.Errorf("expected nil credentials, got %+v", creds)
	}
	if source != "" {
		t.Errorf("source = %q, want empty", source)
	}
}

func TestClientBuildsCorrectAuth(t *testing.T) {
	apiCreds := &Credentials{Method: MethodAPIKey, APIKey: "tok"}
	c, err := Client(apiCreds)
	if err != nil {
		t.Fatal(err)
	}
	if c.APIKey != "tok" {
		t.Errorf("APIKey = %q, want tok", c.APIKey)
	}
	if c.Auth != nil {
		t.Errorf("API-key client should have nil Auth")
	}
	if c.Tailnet != "-" {
		t.Errorf("Tailnet = %q, want \"-\"", c.Tailnet)
	}

	oauthCreds := &Credentials{Method: MethodOAuth, ClientID: "cid", ClientSecret: "csec", Tailnet: "ts.net.example"}
	c, err = Client(oauthCreds)
	if err != nil {
		t.Fatal(err)
	}
	if c.APIKey != "" {
		t.Errorf("OAuth client should not set APIKey, got %q", c.APIKey)
	}
	oauth, ok := c.Auth.(*tailscale.OAuth)
	if !ok {
		t.Fatalf("Auth type = %T, want *tailscale.OAuth", c.Auth)
	}
	if oauth.ClientID != "cid" || oauth.ClientSecret != "csec" {
		t.Errorf("OAuth fields = %q/%q, want cid/csec", oauth.ClientID, oauth.ClientSecret)
	}
	if c.Tailnet != "ts.net.example" {
		t.Errorf("Tailnet = %q, want ts.net.example", c.Tailnet)
	}

	// Unset tailnet defaults to "-".
	c, err = Client(&Credentials{Method: MethodOAuth, ClientID: "cid", ClientSecret: "csec"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Tailnet != "-" {
		t.Errorf("default Tailnet = %q, want \"-\"", c.Tailnet)
	}

	if _, err := Client(&Credentials{Method: "bogus"}); err == nil {
		t.Error("expected error for unknown method")
	}
	if _, err := Client(&Credentials{Method: MethodAPIKey}); err == nil {
		t.Error("expected error for empty API key")
	}
	if _, err := Client(&Credentials{Method: MethodOAuth, ClientID: "cid"}); err == nil {
		t.Error("expected error for OAuth missing secret")
	}
}

// Verify requires network access; it is intentionally not exercised here.
var _ = context.Background

func TestSaveLeavesCustomParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not model POSIX directory modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Credentials{Method: MethodAPIKey, APIKey: "k"}, filepath.Join(dir, "config.json")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("existing parent perms = %o, want 755", perm)
	}
}

func TestVerifyDoesNotClaimCallerIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[{"loginName":"someone-else@example.com"}]}`))
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := Verify(context.Background(), &tailscale.Client{BaseURL: base, APIKey: "k", Tailnet: "-"})
	if err != nil {
		t.Fatal(err)
	}
	if summary != "connected (1 users visible)" {
		t.Errorf("summary = %q", summary)
	}
}

// Package auth resolves, stores, and validates taildoc credentials
// (Tailscale API keys or OAuth clients).
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/fileutil"
)

const (
	// MethodAPIKey identifies API-key credentials.
	MethodAPIKey = "apikey"
	// MethodOAuth identifies OAuth client credentials.
	MethodOAuth = "oauth"
)

// Credentials describes one way of authenticating against the Tailscale API.
type Credentials struct {
	Method       string `json:"method"` // "apikey" | "oauth"
	APIKey       string `json:"apiKey,omitempty"`
	ClientID     string `json:"clientID,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Tailnet      string `json:",omitempty"`
}

// DefaultPath returns the config file location: $TAILDOC_CONFIG if set,
// otherwise <user config dir>/taildoc/config.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("TAILDOC_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := defaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func defaultConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	return filepath.Join(dir, "taildoc"), nil
}

// Load reads credentials from path. It returns (nil, nil) if the file does
// not exist.
func Load(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

// Save writes credentials to path, creating missing parent directories with
// mode 0700 and the file itself with mode 0600.
func Save(c *Credentials, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	// Only taildoc's own directory is tightened: TAILDOC_CONFIG can point into a
	// shared directory, such as $HOME, whose permissions are not ours to change.
	if defaultDir, err := defaultConfigDir(); err == nil && dir == defaultDir {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("securing config dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := fileutil.WriteFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// Resolve returns credentials following this precedence:
//
//  1. TS_ACCESS_TOKEN environment variable (synthetic apikey credentials,
//     source "env")
//  2. The config file at DefaultPath (source = file path)
//  3. Nothing: (nil, "", nil) — the caller decides what to do.
//
// A non-nil error means resolution failed unexpectedly (e.g. unreadable
// config file).
func Resolve() (*Credentials, string, error) {
	if token := os.Getenv("TS_ACCESS_TOKEN"); token != "" {
		return &Credentials{
			Method:  MethodAPIKey,
			APIKey:  token,
			Tailnet: "-",
		}, "env", nil
	}

	path, err := DefaultPath()
	if err != nil {
		return nil, "", err
	}
	c, err := Load(path)
	if err != nil {
		return nil, "", err
	}
	if c == nil {
		return nil, "", nil
	}
	return c, path, nil
}

// Client builds a tailscale.Client from credentials. OAuth credentials use
// the SDK's Auth field (which auto-fetches tokens); API-key credentials use
// basic auth via the APIKey field. The Tailnet defaults to "-".
func Client(creds *Credentials) (*tailscale.Client, error) {
	if creds == nil {
		return nil, errors.New("no credentials: set TS_ACCESS_TOKEN or run `taildoc auth login`")
	}
	switch creds.Method {
	case MethodOAuth:
		if creds.ClientID == "" || creds.ClientSecret == "" {
			return nil, errors.New("oauth credentials require client ID and secret")
		}
		tailnet := creds.Tailnet
		if tailnet == "" {
			tailnet = "-"
		}
		return &tailscale.Client{
			Tailnet: tailnet,
			Auth: &tailscale.OAuth{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
			},
		}, nil
	case MethodAPIKey:
		if creds.APIKey == "" {
			return nil, errors.New("api key credentials require an API key")
		}
		tailnet := creds.Tailnet
		if tailnet == "" {
			tailnet = "-"
		}
		return &tailscale.Client{
			APIKey:  creds.APIKey,
			Tailnet: tailnet,
		}, nil
	default:
		return nil, fmt.Errorf("unknown auth method %q", creds.Method)
	}
}

// Verify makes a cheap read call against the API and returns a human readable
// summary. The API does not identify the caller, so the summary only reports
// what the credentials can see.
func Verify(ctx context.Context, c *tailscale.Client) (string, error) {
	users, err := c.Users().List(ctx, nil, nil)
	if err != nil {
		return "", fmt.Errorf("verifying credentials: %w", err)
	}
	if c.Auth != nil {
		return fmt.Sprintf("OAuth client valid (%d users visible)", len(users)), nil
	}
	return fmt.Sprintf("connected (%d users visible)", len(users)), nil
}

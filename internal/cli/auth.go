package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/auth"
)

func runAuth(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `Usage:
  taildoc auth login   [--apikey <key> | --oauth-client-id <id> --oauth-client-secret <secret>] [--tailnet <name>]
  taildoc auth status  Show current credentials
  taildoc auth logout  Delete stored credentials
`)
		return errors.New("auth requires a subcommand: login, status, or logout")
	}

	switch args[0] {
	case "login":
		return runAuthLogin(ctx, args[1:])
	case "status":
		return runAuthStatus(ctx)
	case "logout":
		return runAuthLogout()
	default:
		return fmt.Errorf("unknown auth subcommand %q (want login, status, or logout)", args[0])
	}
}

func runAuthLogin(ctx context.Context, args []string) error {
	fs := newFlagSet("auth login")
	apiKey := fs.String("apikey", "", "Tailscale API key")
	clientID := fs.String("oauth-client-id", "", "OAuth client ID (k1234567890abcdef)")
	clientSecret := fs.String("oauth-client-secret", "", "OAuth client secret")
	tailnet := fs.String("tailnet", "-", "tailnet name to operate on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	reader := bufio.NewReader(os.Stdin)

	creds := &auth.Credentials{Tailnet: *tailnet}
	switch {
	case *apiKey != "" && (*clientID != "" || *clientSecret != ""):
		return errors.New("specify either --apikey or OAuth flags, not both")
	case *apiKey != "":
		creds.Method = auth.MethodAPIKey
		creds.APIKey = *apiKey
	case *clientID != "" || *clientSecret != "":
		if *clientID == "" || *clientSecret == "" {
			return errors.New("--oauth-client-id and --oauth-client-secret must be provided together")
		}
		creds.Method = auth.MethodOAuth
		creds.ClientID = *clientID
		creds.ClientSecret = *clientSecret
	default:
		fmt.Println("Choose an authentication method:")
		fmt.Println("  1) API key      https://login.tailscale.com/admin/settings/keys")
		fmt.Println("  2) OAuth client https://login.tailscale.com/admin/settings/oauth")
		fmt.Print("Enter 1 or 2: ")
		choice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading choice: %w", err)
		}
		switch strings.TrimSpace(choice) {
		case "1":
			creds.Method = auth.MethodAPIKey
			v, err := promptLine(reader, "API key: ")
			if err != nil {
				return err
			}
			creds.APIKey = v
		case "2":
			creds.Method = auth.MethodOAuth
			if creds.ClientID, err = promptLine(reader, "OAuth client ID: "); err != nil {
				return err
			}
			if creds.ClientSecret, err = promptLine(reader, "OAuth client secret: "); err != nil {
				return err
			}
		default:
			return errors.New("invalid choice; enter 1 or 2")
		}
	}

	client, err := auth.Client(creds)
	if err != nil {
		return err
	}

	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	summary, err := auth.Verify(verifyCtx, client)
	if err != nil {
		return fmt.Errorf("credentials rejected, nothing saved: %w", err)
	}
	fmt.Println(summary)

	path, err := auth.DefaultPath()
	if err != nil {
		return err
	}
	if err := auth.Save(creds, path); err != nil {
		return err
	}
	fmt.Printf("Credentials saved to %s\n", path)
	return nil
}

func promptLine(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading input: %w", err)
	}
	v := strings.TrimSpace(line)
	if v == "" {
		return "", errors.New("empty value")
	}
	return v, nil
}

func runAuthStatus(ctx context.Context) error {
	creds, source, err := auth.Resolve()
	if err != nil {
		return err
	}
	if creds == nil {
		fmt.Println("not logged in — set TS_ACCESS_TOKEN or run `taildoc auth login`")
		return nil
	}

	method := creds.Method
	if method == "" {
		method = "unknown"
	}
	fmt.Printf("Credentials: method=%s source=%s\n", method, source)

	client, err := auth.Client(creds)
	if err != nil {
		fmt.Printf("Stored credentials are invalid: %v\n", err)
		return nil
	}

	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	summary, err := auth.Verify(verifyCtx, client)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return nil
	}
	fmt.Println(summary)
	return nil
}

func runAuthLogout() error {
	path, err := auth.DefaultPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	switch {
	case err == nil:
		fmt.Printf("Deleted credentials at %s\n", path)
	case errors.Is(err, fs.ErrNotExist):
		fmt.Printf("No stored credentials at %s\n", path)
	default:
		return fmt.Errorf("removing %s: %w", path, err)
	}
	fmt.Println("(TS_ACCESS_TOKEN in your environment, if any, is unaffected.)")
	return nil
}

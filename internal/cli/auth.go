package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/x/term"

	"github.com/huza1fa/taildoc/internal/auth"
)

func runAuth(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `Usage:
	  taildoc auth login   [--apikey-stdin | --oauth-client-id <id> --oauth-client-secret-stdin] [--tailnet <name>]
  taildoc auth status  Show current credentials
  taildoc auth logout  Delete stored credentials
`)
		return errors.New("auth requires a subcommand: login, status, or logout")
	}

	switch args[0] {
	case "login":
		return runAuthLogin(ctx, args[1:])
	case "status":
		if len(args) != 1 {
			return errors.New("usage: taildoc auth status")
		}
		return runAuthStatus(ctx)
	case "logout":
		if len(args) != 1 {
			return errors.New("usage: taildoc auth logout")
		}
		return runAuthLogout()
	default:
		return fmt.Errorf("unknown auth subcommand %q (want login, status, or logout)", args[0])
	}
}

func runAuthLogin(ctx context.Context, args []string) error {
	fs := newFlagSet("auth login")
	apiKeyStdin := fs.Bool("apikey-stdin", false, "read the API key from standard input")
	clientID := fs.String("oauth-client-id", "", "OAuth client ID (k1234567890abcdef)")
	clientSecretStdin := fs.Bool("oauth-client-secret-stdin", false, "read the OAuth client secret from standard input")
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
	case *apiKeyStdin && (*clientID != "" || *clientSecretStdin):
		return errors.New("specify either --apikey-stdin or OAuth flags, not both")
	case *apiKeyStdin:
		creds.Method = auth.MethodAPIKey
		v, err := readSecretStdin()
		if err != nil {
			return err
		}
		creds.APIKey = v
	case *clientID != "" || *clientSecretStdin:
		if *clientID == "" || !*clientSecretStdin {
			return errors.New("--oauth-client-id and --oauth-client-secret-stdin must be provided together")
		}
		creds.Method = auth.MethodOAuth
		creds.ClientID = *clientID
		v, err := readSecretStdin()
		if err != nil {
			return err
		}
		creds.ClientSecret = v
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
			v, err := promptSecret("API key: ")
			if err != nil {
				return err
			}
			creds.APIKey = v
		case "2":
			creds.Method = auth.MethodOAuth
			if creds.ClientID, err = promptLine(reader, "OAuth client ID: "); err != nil {
				return err
			}
			if creds.ClientSecret, err = promptSecret("OAuth client secret: "); err != nil {
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

func readSecretStdin() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading secret from standard input: %w", err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", errors.New("empty secret")
	}
	return v, nil
}

func promptSecret(label string) (string, error) {
	if !term.IsTerminal(os.Stdin.Fd()) {
		return "", errors.New("standard input is not a terminal; use --apikey-stdin or --oauth-client-secret-stdin")
	}
	fmt.Print(label)
	data, err := term.ReadPassword(os.Stdin.Fd())
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", errors.New("empty value")
	}
	return v, nil
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
		return errors.New("no credentials configured")
	}

	method := creds.Method
	if method == "" {
		method = "unknown"
	}
	fmt.Printf("Credentials: method=%s source=%s\n", method, source)

	client, err := auth.Client(creds)
	if err != nil {
		fmt.Printf("Stored credentials are invalid: %v\n", err)
		return err
	}

	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	summary, err := auth.Verify(verifyCtx, client)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return err
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

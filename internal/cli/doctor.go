package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/huza1fa/taildoc/internal/auth"
)

type doctorStatus string

const (
	doctorOK      doctorStatus = "ok"
	doctorWarning doctorStatus = "warning"
	doctorFailed  doctorStatus = "failed"
)

type doctorCheck struct {
	Name   string
	Status doctorStatus
	Detail string
}

func runDoctor(ctx context.Context, args []string) error {
	fs := newFlagSet("doctor")
	checkAPI := fs.Bool("check-api", false, "verify credentials with a read-only API request")
	collectLive := fs.Bool("collect", false, "exercise the full live collection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: taildoc doctor [--check-api] [--collect]")
	}

	checks, creds := localDoctorChecks()
	if creds != nil && *checkAPI {
		client, err := auth.Client(creds)
		if err != nil {
			checks = append(checks, doctorCheck{"API credentials", doctorFailed, err.Error()})
		} else {
			summary, err := auth.Verify(ctx, client)
			if err != nil {
				checks = append(checks, doctorCheck{"API credentials", doctorFailed, err.Error()})
			} else {
				checks = append(checks, doctorCheck{"API credentials", doctorOK, summary})
			}
		}
	}
	if *collectLive {
		if _, err := collect(ctx); err != nil {
			checks = append(checks, doctorCheck{"live collection", doctorFailed, err.Error()})
		} else {
			checks = append(checks, doctorCheck{"live collection", doctorOK, "users, devices, and policy are readable"})
		}
	}

	failed := false
	for _, check := range checks {
		marker := "OK"
		switch check.Status {
		case doctorWarning:
			marker = "WARN"
		case doctorFailed:
			marker = "FAIL"
			failed = true
		}
		fmt.Printf("[%s] %s: %s\n", marker, check.Name, check.Detail)
	}
	if failed {
		return ErrDoctorFailed
	}
	return nil
}

// localDoctorChecks performs only local checks. It intentionally reports no
// credential values, identifiers, or file contents.
func localDoctorChecks() ([]doctorCheck, *auth.Credentials) {
	path, err := auth.DefaultPath()
	if err != nil {
		return []doctorCheck{{"config path", doctorFailed, err.Error()}}, nil
	}

	checks := configSafetyChecks(path)
	creds, source, err := auth.Resolve()
	if err != nil {
		return append(checks, doctorCheck{"credentials", doctorFailed, err.Error()}), nil
	}
	if creds == nil {
		return append(checks, doctorCheck{"credentials", doctorFailed, "not configured; set TS_ACCESS_TOKEN or run `taildoc auth login`"}), nil
	}
	if _, err := auth.Client(creds); err != nil {
		return append(checks, doctorCheck{"credentials", doctorFailed, err.Error()}), nil
	}

	detail := fmt.Sprintf("%s credentials available from %s", credentialsMethodLabel(creds.Method), credentialSourceLabel(source, path))
	return append(checks, doctorCheck{"credentials", doctorOK, detail}), creds
}

func credentialsMethodLabel(method string) string {
	switch method {
	case auth.MethodAPIKey:
		return "API key"
	case auth.MethodOAuth:
		return "OAuth"
	default:
		return "unknown"
	}
}

func credentialSourceLabel(source, configPath string) string {
	if source == "env" {
		return "TS_ACCESS_TOKEN environment variable"
	}
	if source == configPath {
		return "config file"
	}
	return "configured source"
}

func configSafetyChecks(path string) []doctorCheck {
	var checks []doctorCheck
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		checks = append(checks, doctorCheck{"config file", doctorOK, "not present (environment credentials may still be used)"})
	case err != nil:
		checks = append(checks, doctorCheck{"config file", doctorFailed, fmt.Sprintf("cannot inspect %s: %v", path, err)})
	case info.Mode()&os.ModeSymlink != 0:
		checks = append(checks, doctorCheck{"config file", doctorWarning, "is a symbolic link; use a regular file with mode 0600 for stored credentials"})
	case !info.Mode().IsRegular():
		checks = append(checks, doctorCheck{"config file", doctorWarning, "is not a regular file"})
	case info.Mode().Perm()&0o077 != 0:
		checks = append(checks, doctorCheck{"config file", doctorWarning, fmt.Sprintf("permissions are %04o; expected 0600", info.Mode().Perm())})
	default:
		checks = append(checks, doctorCheck{"config file", doctorOK, "regular file with private permissions"})
	}

	dir := filepath.Dir(path)
	dirInfo, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		checks = append(checks, doctorCheck{"config directory", doctorOK, "not present; it will be created privately when credentials are saved"})
	case err != nil:
		checks = append(checks, doctorCheck{"config directory", doctorFailed, fmt.Sprintf("cannot inspect %s: %v", dir, err)})
	case !dirInfo.IsDir():
		checks = append(checks, doctorCheck{"config directory", doctorFailed, "is not a directory"})
	case dirInfo.Mode().Perm()&0o077 != 0:
		checks = append(checks, doctorCheck{"config directory", doctorWarning, fmt.Sprintf("permissions are %04o; expected 0700", dirInfo.Mode().Perm())})
	default:
		checks = append(checks, doctorCheck{"config directory", doctorOK, "private permissions"})
	}
	return checks
}

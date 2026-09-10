package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/auth"
)

func TestLocalDoctorChecksReportsPrivateConfigWithoutLeakingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taildoc", "config.json")
	t.Setenv("TAILDOC_CONFIG", path)
	t.Setenv("TS_ACCESS_TOKEN", "")
	if err := auth.Save(&auth.Credentials{Method: auth.MethodAPIKey, APIKey: "super-secret-token"}, path); err != nil {
		t.Fatal(err)
	}

	checks, creds := localDoctorChecks()
	if creds == nil {
		t.Fatal("expected configured credentials")
	}
	if hasDoctorStatus(checks, "config file", doctorWarning) || hasDoctorStatus(checks, "config file", doctorFailed) {
		t.Errorf("private config was not accepted: %#v", checks)
	}
	if !hasDoctorStatus(checks, "credentials", doctorOK) {
		t.Errorf("credentials not reported as available: %#v", checks)
	}
	for _, check := range checks {
		if strings.Contains(check.Detail, "super-secret-token") {
			t.Fatalf("doctor leaked secret in %#v", check)
		}
	}
}

func TestConfigSafetyChecksWarnsOnBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := auth.Save(&auth.Credentials{Method: auth.MethodAPIKey, APIKey: "secret"}, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	checks := configSafetyChecks(path)
	if !hasDoctorStatus(checks, "config file", doctorWarning) {
		t.Errorf("expected config permissions warning, got %#v", checks)
	}
}

func TestLocalDoctorChecksReportsMissingCredentials(t *testing.T) {
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("TS_ACCESS_TOKEN", "")

	checks, creds := localDoctorChecks()
	if creds != nil {
		t.Fatal("expected no credentials")
	}
	if !hasDoctorStatus(checks, "credentials", doctorFailed) {
		t.Errorf("expected credentials failure, got %#v", checks)
	}
}

func hasDoctorStatus(checks []doctorCheck, name string, status doctorStatus) bool {
	for _, check := range checks {
		if check.Name == name && check.Status == status {
			return true
		}
	}
	return false
}

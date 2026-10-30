package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/audit"
)

func testFindings() []audit.Finding {
	return []audit.Finding{
		{
			Severity: audit.High,
			Title:    "Grant allows everything",
			Detail:   "Wildcard grant found.",
			Evidence: []string{"src: autogroup:member", "dst: *"},
			Why:      "Neutralizes access control.",
			Next:     "Restrict the grant.",
		},
		{
			Severity: audit.Low,
			Title:    "Only one exit node exists",
			Evidence: []string{"device: host-a (linux, alice)"},
			Why:      "Single point of failure.",
			Next:     "Add a second exit node.",
		},
	}
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordAndReopen(t *testing.T) {
	path := t.TempDir() + "/hist.db"
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Record(testFindings(), at); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.FindingsAt(at)
	if err != nil {
		t.Fatalf("FindingsAt: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	want := testFindings()[0]
	if got[0].Severity != want.Severity || got[0].Title != want.Title ||
		got[0].Detail != want.Detail || got[0].Why != want.Why || got[0].Next != want.Next {
		t.Errorf("finding mismatch:\n got %+v\nwant %+v", got[0], want)
	}
	if len(got[0].Evidence) != 2 || got[0].Evidence[0] != "src: autogroup:member" || got[0].Evidence[1] != "dst: *" {
		t.Errorf("evidence round-trip failed: %q", got[0].Evidence)
	}
}

func TestNewFindings(t *testing.T) {
	s := openTemp(t)

	all := testFindings()
	fresh := audit.Finding{Severity: audit.Medium, Title: "New problem", Detail: "Just appeared."}

	newer, err := s.NewFindings(append(all, fresh))
	if err != nil {
		t.Fatalf("NewFindings on empty store: %v", err)
	}
	if len(newer) != 3 {
		t.Fatalf("empty store: got %d new findings, want 3", len(newer))
	}

	if err := s.Record(all, time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}

	newer, err = s.NewFindings(append(all, fresh))
	if err != nil {
		t.Fatalf("NewFindings: %v", err)
	}
	if len(newer) != 1 || newer[0].Title != fresh.Title {
		t.Fatalf("got %+v, want only %q", newer, fresh.Title)
	}
}

func TestLatestRun(t *testing.T) {
	s := openTemp(t)

	if _, ok, err := s.LatestRun(); err != nil || ok {
		t.Fatalf("LatestRun on empty store: ok=%v err=%v, want false/nil", ok, err)
	}

	first := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	second := time.Date(2026, 8, 21, 11, 30, 0, 0, time.UTC)
	if err := s.Record(testFindings(), first); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record([]audit.Finding{{Severity: audit.Info, Title: "later"}}, second); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, ok, err := s.LatestRun()
	if err != nil || !ok {
		t.Fatalf("LatestRun: ok=%v err=%v", ok, err)
	}
	if !got.Equal(second) {
		t.Errorf("got %v, want %v", got, second)
	}
}

func TestRecordEmptyRun(t *testing.T) {
	s := openTemp(t)
	at := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	if err := s.Record(nil, at); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, ok, err := s.LatestRun()
	if err != nil || !ok || !got.Equal(at) {
		t.Fatalf("LatestRun = %v, %v, %v; want %v, true, nil", got, ok, err, at)
	}
}

func TestFingerprintIncludesEvidence(t *testing.T) {
	a := audit.Finding{Severity: audit.High, Title: "Grant allows all ports", Evidence: []string{"src: tag:a"}}
	b := audit.Finding{Severity: audit.High, Title: "Grant allows all ports", Evidence: []string{"src: tag:b"}}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("distinct affected grants must have distinct fingerprints")
	}
}

func TestRunsOrdering(t *testing.T) {
	s := openTemp(t)
	a := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	b := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	if err := s.Record(testFindings(), a); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(testFindings(), b); err != nil {
		t.Fatalf("Record: %v", err)
	}
	runs, err := s.Runs()
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	if len(runs) != 2 || !runs[0].Equal(a) || !runs[1].Equal(b) {
		t.Fatalf("got runs %v, want [%v %v]", runs, a, b)
	}
}

func TestPruneKeepsNewestRuns(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	finding := audit.Finding{RuleID: "stale-devices", Subject: "x", Severity: audit.Low, Title: "t"}
	for i := 0; i < 5; i++ {
		if err := store.Record([]audit.Finding{finding}, base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := store.Prune(2)
	if err != nil || removed != 3 {
		t.Fatalf("Prune(2) = %d, %v", removed, err)
	}
	runs, err := store.Runs()
	if err != nil || len(runs) != 2 || !runs[0].Equal(base.Add(3*time.Hour)) {
		t.Fatalf("runs = %v, %v", runs, err)
	}
	if old, err := store.FindingsAt(base); err != nil || len(old) != 0 {
		t.Fatalf("findings of pruned run = %v, %v", old, err)
	}
	if kept, err := store.FindingsAt(base.Add(4 * time.Hour)); err != nil || len(kept) != 1 {
		t.Fatalf("findings of kept run = %v, %v", kept, err)
	}
	if removed, err := store.Prune(10); err != nil || removed != 0 {
		t.Fatalf("Prune(10) = %d, %v", removed, err)
	}
	if _, err := store.Prune(0); err == nil {
		t.Fatal("Prune(0) must not empty the history")
	}
}

func TestDefaultPathSharesConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("AppData", dir)
	path, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "history.db" || filepath.Base(filepath.Dir(path)) != "taildoc" {
		t.Fatalf("path = %q", path)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("default parent must exist: %v", err)
	}
	store.Close()
}

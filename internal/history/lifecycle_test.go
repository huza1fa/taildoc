package history

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestFindingLifecycleAndFilters(t *testing.T) {
	s := openTemp(t)
	at := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	f := audit.Finding{RuleID: "stale-devices", Subject: "90-days", Severity: audit.Medium, Title: "1 device(s) unseen for over 90 days", Evidence: []string{"one, last seen yesterday"}}
	if err := s.Record([]audit.Finding{f}, at); err != nil {
		t.Fatal(err)
	}
	f.Title = "2 device(s) unseen for over 90 days"
	f.Evidence = []string{"one, last seen today", "two"}
	if err := s.Record([]audit.Finding{f}, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(nil, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record([]audit.Finding{f}, at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	runs, err := s.Timeline(Query{})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []Status{Reopened, Resolved, Ongoing, New} {
		if len(runs[i].Events) != 1 || runs[i].Events[0].Status != want {
			t.Fatalf("run %d: %+v, want %s", i, runs[i], want)
		}
	}
	runs, err = s.Timeline(Query{Limit: 1, Since: at.Add(time.Second), Status: Reopened, Severity: audit.Medium, RuleID: "stale-devices"})
	if err != nil || len(runs) != 1 || runs[0].Events[0].Status != Reopened {
		t.Fatalf("filtered runs: %+v %v", runs, err)
	}
	runs, err = s.Timeline(Query{Limit: 1, Status: New})
	if err != nil || len(runs) != 0 {
		t.Fatalf("limit applies before filters: %+v %v", runs, err)
	}
	for _, q := range []Query{{Limit: -1}, {Status: "bogus"}, {Severity: "critical"}, {RuleID: "bogus"}} {
		if _, err := s.Timeline(q); err == nil {
			t.Errorf("accepted invalid query: %+v", q)
		}
	}
}
func TestAuditIdentitySurvivesEvidenceAndDeviceRename(t *testing.T) {
	now := time.Now()
	tn := &tailnet.Tailnet{CollectedAt: now, Devices: []*tailnet.Device{{ID: "stable-id", Hostname: "router-a", AdvertisedRoutes: []string{"10.0.0.0/24"}, LastSeen: now.Add(-100 * 24 * time.Hour)}}}
	a := audit.RunFiltered(tn, []string{"stale-devices", "unapproved-routes"}, nil)
	tn.Devices[0].Hostname = "router-b"
	tn.Devices[0].LastSeen = now.Add(-101 * 24 * time.Hour)
	b := audit.RunFiltered(tn, []string{"stale-devices", "unapproved-routes"}, nil)
	for i := range a {
		if Fingerprint(a[i]) != Fingerprint(b[i]) {
			t.Errorf("identity changed: %+v -> %+v", a[i], b[i])
		}
	}
}
func TestHistoryMigratesExistingDatabaseAndSubsecondOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT,recorded_at TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,detail TEXT,why TEXT,next TEXT,evidence TEXT,fingerprint TEXT NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	f := testFindings()[0]
	ts := "2026-10-19T10:00:00Z"
	_, err = db.Exec(`INSERT INTO findings(recorded_at,severity,title,detail,why,next,evidence,fingerprint) VALUES(?,?,?,?,?,?,?,?)`, ts, f.Severity, f.Title, f.Detail, f.Why, f.Next, "", Fingerprint(f))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at, _ := time.Parse(time.RFC3339, ts)
	if err := s.Record(nil, at.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	latest, ok, err := s.LatestRun()
	if err != nil || !ok || !latest.Equal(at.Add(time.Nanosecond)) {
		t.Fatalf("latest: %v %v %v", latest, ok, err)
	}
	runs, err := s.Timeline(Query{Limit: 1})
	if err != nil || len(runs) != 1 || len(runs[0].Events) != 1 || runs[0].Events[0].Status != Resolved {
		t.Fatalf("legacy lifecycle: %+v %v", runs, err)
	}
}

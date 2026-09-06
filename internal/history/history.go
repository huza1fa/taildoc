// Package history persists audit findings locally in SQLite so users can
// track issues over time and identify which findings are new.
package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/huza1fa/taildoc/internal/audit"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Single writer: modernc sqlite is a file DB; concurrent opens from
	// cron + manual runs otherwise hit "database is locked" flakily.
	db.SetMaxOpenConns(1)
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA busy_timeout=5000`,
		`PRAGMA synchronous=NORMAL`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recorded_at TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		detail TEXT,
		why TEXT,
		next TEXT,
		evidence TEXT,
		fingerprint TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS runs (
		recorded_at TEXT PRIMARY KEY
	)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO runs (recorded_at)
		SELECT DISTINCT recorded_at FROM findings`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_recorded_at ON findings(recorded_at)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Fingerprint returns the stable identity of a finding across runs.
// Titles embed counts ("3 device(s) ...") so the leading count is stripped;
// otherwise 2 -> 3 devices of the same issue would look like a new finding.
func Fingerprint(f audit.Finding) string {
	evidence := append([]string(nil), f.Evidence...)
	sort.Strings(evidence)
	h := sha256.Sum256([]byte(string(f.Severity) + "\x00" + normalizeTitle(f.Title) + "\x00" + f.Detail + "\x00" + strings.Join(evidence, "\x00")))
	return hex.EncodeToString(h[:])
}

var countPrefix = regexp.MustCompile(`^\d+\s+\S+(\(s\))?\s+(defined\s+in\s+|with\s+|still\s+|inactive\s+|unseen\s+|have\s+)?`)

func normalizeTitle(t string) string {
	if loc := countPrefix.FindStringIndex(t); loc != nil && loc[0] == 0 {
		return strings.TrimSpace(t[loc[1]:])
	}
	return t
}

func (s *Store) Record(findings []audit.Finding, at time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO findings
		(recorded_at, severity, title, detail, why, next, evidence, fingerprint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	ts := at.UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO runs (recorded_at) VALUES (?)`, ts); err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := stmt.Exec(ts, f.Severity, f.Title, f.Detail, f.Why, f.Next,
			strings.Join(f.Evidence, "\n"), Fingerprint(f)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LatestRun() (time.Time, bool, error) {
	var ts string
	err := s.db.QueryRow(`SELECT recorded_at FROM runs ORDER BY recorded_at DESC LIMIT 1`).Scan(&ts)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := parseTime(ts)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (s *Store) KnownFingerprints() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT fingerprint FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out[fp] = true
	}
	return out, rows.Err()
}

func (s *Store) NewFindings(findings []audit.Finding) ([]audit.Finding, error) {
	// Compare against the latest run only (not all-ever history): bounded,
	// and a fixed-then-reintroduced issue correctly shows as new again.
	latest, ok, err := s.LatestRun()
	if err != nil {
		return nil, err
	}
	if !ok {
		return append([]audit.Finding(nil), findings...), nil
	}
	prev, err := s.FindingsAt(latest)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(prev))
	for _, f := range prev {
		known[Fingerprint(f)] = true
	}
	var out []audit.Finding
	for _, f := range findings {
		if !known[Fingerprint(f)] {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *Store) Runs() ([]time.Time, error) {
	rows, err := s.db.Query(`SELECT recorded_at FROM runs ORDER BY recorded_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		t, err := parseTime(ts)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) FindingsAt(at time.Time) ([]audit.Finding, error) {
	rows, err := s.db.Query(`SELECT severity, title, detail, why, next, evidence
		FROM findings WHERE recorded_at = ?
		ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END, title, detail`,
		at.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Finding
	for rows.Next() {
		var f audit.Finding
		var ev sql.NullString
		if err := rows.Scan(&f.Severity, &f.Title, &f.Detail, &f.Why, &f.Next, &ev); err != nil {
			return nil, err
		}
		if ev.Valid && ev.String != "" {
			f.Evidence = strings.Split(ev.String, "\n")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }

func parseTime(ts string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, ts)
}

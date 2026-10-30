// Package history persists audit findings locally in SQLite so users can
// track issues over time and identify which findings are new.
package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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

// DefaultPath returns the database beside taildoc's config, so scheduled and
// manual runs share one history whatever directory they start in. It creates
// the private directory because Open expects its parent to exist.
func DefaultPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	dir := filepath.Join(base, "taildoc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating history dir: %w", err)
	}
	return filepath.Join(dir, "history.db"), nil
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
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_fp_at ON findings(fingerprint, recorded_at)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_recorded_at ON findings(recorded_at)`); err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// Fingerprint returns the stable identity of a finding across runs.
// Built-in checks identify their rule and subject independently of evidence.
// Older findings use the original evidence-based identity for compatibility.
func Fingerprint(f audit.Finding) string {
	if f.RuleID != "" && f.Subject != "" {
		h := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Subject))
		return hex.EncodeToString(h[:])
	}
	return legacyFingerprint(f)
}
func legacyFingerprint(f audit.Finding) string {
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
		(recorded_at, severity, title, detail, why, next, evidence, fingerprint, rule_id, subject)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	ts := timeKey(at)
	if _, err := tx.Exec(`INSERT INTO runs (recorded_at) VALUES (?)`, ts); err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := stmt.Exec(ts, f.Severity, f.Title, f.Detail, f.Why, f.Next,
			strings.Join(f.Evidence, "\n"), Fingerprint(f), f.RuleID, f.Subject); err != nil {
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
		known[legacyFingerprint(f)] = true
	}
	var out []audit.Finding
	for _, f := range findings {
		if !known[Fingerprint(f)] && !known[legacyFingerprint(f)] {
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
	rows, err := s.db.Query(`SELECT severity, title, detail, why, next, evidence, rule_id, subject
		FROM findings WHERE recorded_at = ?
		ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END, title, detail`,
		timeKey(at))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Finding
	for rows.Next() {
		var f audit.Finding
		var ev sql.NullString
		if err := rows.Scan(&f.Severity, &f.Title, &f.Detail, &f.Why, &f.Next, &ev, &f.RuleID, &f.Subject); err != nil {
			return nil, err
		}
		if ev.Valid && ev.String != "" {
			f.Evidence = strings.Split(ev.String, "\n")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Prune keeps the newest keep runs and returns how many it removed. Findings
// seen only in removed runs stop counting as history, so one that returns later
// is reported as new rather than reopened.
func (s *Store) Prune(keep int) (int, error) {
	if keep < 1 {
		return 0, fmt.Errorf("prune must keep at least one run")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cutoff string
	err = tx.QueryRow(`SELECT recorded_at FROM runs ORDER BY recorded_at DESC LIMIT 1 OFFSET ?`, keep-1).Scan(&cutoff)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM findings WHERE recorded_at < ?`, cutoff); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`DELETE FROM runs WHERE recorded_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(removed), tx.Commit()
}

func (s *Store) Close() error { return s.db.Close() }

func parseTime(ts string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, ts)
}

// Fixed precision makes textual ordering correct even within the same second.
func timeKey(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= 1 {
		return nil
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO runs(recorded_at) SELECT DISTINCT recorded_at FROM findings`); err != nil {
		return err
	}
	rows, err := s.db.Query(`PRAGMA table_info(findings)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, col := range []string{"rule_id", "subject"} {
		if !columns[col] {
			if _, err := s.db.Exec(fmt.Sprintf("ALTER TABLE findings ADD COLUMN %s TEXT NOT NULL DEFAULT ''", col)); err != nil {
				return err
			}
		}
	}
	rows, err = s.db.Query(`SELECT recorded_at FROM runs`)
	if err != nil {
		return err
	}
	var stamps []string
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			rows.Close()
			return err
		}
		stamps = append(stamps, ts)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, ts := range stamps {
		at, err := parseTime(ts)
		if err != nil {
			return err
		}
		key := timeKey(at)
		if ts == key {
			continue
		}
		if _, err = tx.Exec(`UPDATE findings SET recorded_at=? WHERE recorded_at=?`, key, ts); err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO runs(recorded_at) VALUES (?)`, key); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM runs WHERE recorded_at=?`, ts); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`PRAGMA user_version=1`); err != nil {
		return err
	}
	return tx.Commit()
}

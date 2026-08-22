// Package history persists audit findings locally in SQLite so users can
// track issues over time and identify which findings are new.
package history

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/huza1fa/taildoc/internal/audit"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
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
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Fingerprint returns the stable identity of a finding across runs.
func Fingerprint(f audit.Finding) string {
	h := sha256.Sum256([]byte(string(f.Severity) + "\x00" + f.Title))
	return hex.EncodeToString(h[:])
}

func (s *Store) Record(findings []audit.Finding, at time.Time) error {
	tx, err := s.db.Begin()
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
	err := s.db.QueryRow(`SELECT recorded_at FROM findings ORDER BY id DESC LIMIT 1`).Scan(&ts)
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
	known, err := s.KnownFingerprints()
	if err != nil {
		return nil, err
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
	rows, err := s.db.Query(`SELECT recorded_at FROM findings GROUP BY recorded_at ORDER BY MIN(id)`)
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
		ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END`,
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

package history

import (
	"fmt"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/audit"
)

type Status string

const (
	New      Status = "new"
	Ongoing  Status = "ongoing"
	Resolved Status = "resolved"
	Reopened Status = "reopened"
)

type Event struct {
	Status  Status        `json:"status"`
	Finding audit.Finding `json:"finding"`
}
type Run struct {
	At     time.Time `json:"at"`
	Events []Event   `json:"events"`
}
type Query struct {
	Limit    int // 0 means all runs
	Since    time.Time
	Status   Status
	Severity audit.Severity
	RuleID   string
}

func ValidateQuery(q Query) error {
	if q.Limit < 0 {
		return fmt.Errorf("history limit must be non-negative")
	}
	switch q.Status {
	case "", New, Ongoing, Resolved, Reopened:
	default:
		return fmt.Errorf("unknown history status %q", q.Status)
	}
	switch q.Severity {
	case "", audit.High, audit.Medium, audit.Low, audit.Info:
	default:
		return fmt.Errorf("unknown severity %q", q.Severity)
	}
	if q.RuleID != "" {
		found := false
		for _, n := range audit.CheckNames {
			if n == q.RuleID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unknown check %q", q.RuleID)
		}
	}
	return nil
}

// Timeline returns recent runs, newest first. Each selected run is compared
// with its actual predecessor, even when that predecessor is outside a filter.
// Limit counts runs before finding filters, keeping the query bounded.
func (s *Store) Timeline(q Query) ([]Run, error) {
	if err := ValidateQuery(q); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT recorded_at FROM runs WHERE recorded_at >= ? ORDER BY recorded_at DESC LIMIT ?`, timeKey(q.Since), sqlLimit(q.Limit))
	if err != nil {
		return nil, err
	}
	var times []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			rows.Close()
			return nil, err
		}
		at, err := parseTime(ts)
		if err != nil {
			rows.Close()
			return nil, err
		}
		times = append(times, at)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	runs := make([]Run, 0, len(times))
	for _, at := range times {
		current, err := s.FindingsAt(at)
		if err != nil {
			return nil, err
		}
		events, err := s.compareBefore(current, at)
		if err != nil {
			return nil, err
		}
		filtered := make([]Event, 0, len(events))
		for _, e := range events {
			if q.Status != "" && e.Status != q.Status {
				continue
			}
			if q.Severity != "" && e.Finding.Severity != q.Severity {
				continue
			}
			if q.RuleID != "" && e.Finding.RuleID != q.RuleID {
				continue
			}
			filtered = append(filtered, e)
		}
		// Keep clean runs visible, unless a finding filter explicitly selected nothing.
		if len(filtered) > 0 || (q.Status == "" && q.Severity == "" && q.RuleID == "") {
			runs = append(runs, Run{at, filtered})
		}
	}
	return runs, nil
}
func sqlLimit(n int) int {
	if n == 0 {
		return -1
	}
	return n
}

func findingKeys(fs []audit.Finding) map[string]bool {
	keys := map[string]bool{}
	for _, f := range fs {
		keys[Fingerprint(f)] = true
		keys[legacyFingerprint(f)] = true
	}
	return keys
}
func hasFinding(keys map[string]bool, f audit.Finding) bool {
	return keys[Fingerprint(f)] || keys[legacyFingerprint(f)]
}

// Preview classifies a prospective run without changing the database.
func (s *Store) Preview(findings []audit.Finding, at time.Time) ([]Event, error) {
	return s.compareBefore(findings, at)
}
func (s *Store) compareBefore(current []audit.Finding, at time.Time) ([]Event, error) {
	var previous string
	err := s.db.QueryRow(`SELECT COALESCE(MAX(recorded_at),'') FROM runs WHERE recorded_at < ?`, timeKey(at)).Scan(&previous)
	if err != nil {
		return nil, err
	}
	var prev []audit.Finding
	if previous != "" {
		p, err := parseTime(previous)
		if err != nil {
			return nil, err
		}
		prev, err = s.FindingsAt(p)
		if err != nil {
			return nil, err
		}
	}
	prior := findingKeys(prev)
	now := findingKeys(current)
	events := make([]Event, 0, len(current)+len(prev))
	for _, f := range current {
		status := New
		if hasFinding(prior, f) {
			status = Ongoing
		} else {
			var seen bool
			err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM findings WHERE fingerprint IN (?,?) AND recorded_at < ?)`, Fingerprint(f), legacyFingerprint(f), timeKey(at)).Scan(&seen)
			if err != nil {
				return nil, err
			}
			if seen {
				status = Reopened
			}
		}
		events = append(events, Event{status, f})
	}
	for _, f := range prev {
		if !hasFinding(now, f) {
			events = append(events, Event{Resolved, f})
		}
	}
	return events, nil
}

func ParseSeverity(s string) audit.Severity { return audit.Severity(strings.ToUpper(s)) }

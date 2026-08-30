// Package snapshot persists and restores tailnet snapshots as JSON.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/fileutil"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Save writes t to path as indented JSON.
func Save(t *tailnet.Tailnet, path string) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	data = append(data, '\n')
	if err := fileutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write snapshot %s: %w", path, err)
	}
	return nil
}

// Load reads a snapshot from path.
func Load(path string) (*tailnet.Tailnet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var t tailnet.Tailnet
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	return &t, nil
}

// SaveDefault writes the snapshot to a timestamped file in the current
// directory and returns the path used.
func SaveDefault(t *tailnet.Tailnet) (string, error) {
	stamp := time.Now().Format(time.RFC3339Nano)
	stamp = strings.NewReplacer(":", "-", ".", "-").Replace(stamp)
	path := fmt.Sprintf("taildoc-snapshot-%s.json", stamp)
	if err := Save(t, path); err != nil {
		return "", err
	}
	return path, nil
}

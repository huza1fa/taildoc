package cli

import (
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestFindTailnetSearchesEveryResourceType(t *testing.T) {
	tailnet := &tailnet.Tailnet{
		Devices: []*tailnet.Device{{Hostname: "prod-db", Owner: "alice@example.com", Tags: []string{"tag:prod"}, Addresses: []string{"100.64.0.4"}}},
		Users:   []*tailnet.User{{LoginName: "alice@example.com", DisplayName: "Alice Example"}},
		Groups:  map[string][]string{"group:platform": {"alice@example.com"}},
		TagOwners: map[string][]string{
			"tag:prod": {"group:platform"},
		},
		Hosts: map[string]string{"database": "100.64.0.4"},
	}

	for _, tc := range []struct {
		query string
		kind  string
		name  string
	}{
		{"prod", "device", "prod-db"},
		{"alice", "user", "alice@example.com"},
		{"platform", "group", "group:platform"},
		{"database", "host", "database"},
		{"100.64.0.4", "device", "prod-db"},
	} {
		found := findTailnet(tailnet, tc.query)
		if !hasResult(found, tc.kind, tc.name) {
			t.Errorf("findTailnet(%q) did not include %s %q: %#v", tc.query, tc.kind, tc.name, found)
		}
	}
}

func TestFindTailnetSupportsFuzzyMatching(t *testing.T) {
	got := findTailnet(&tailnet.Tailnet{Devices: []*tailnet.Device{{Hostname: "production-db"}}}, "pdb")
	if !hasResult(got, "device", "production-db") {
		t.Fatalf("fuzzy search did not find device: %#v", got)
	}
}

func TestMatchScorePrefersExactAndSubstringMatches(t *testing.T) {
	if exact, contains := matchScore("prod", "prod"), matchScore("prod", "my-prod-db"); exact <= contains {
		t.Fatalf("exact score %d should exceed substring score %d", exact, contains)
	}
}

func TestCompletionScriptsMentionNewNavigationCommands(t *testing.T) {
	for _, script := range []string{bashCompletion, zshCompletion, fishCompletion} {
		for _, command := range []string{"find", "show", "doctor", "watch"} {
			if !strings.Contains(script, command) {
				t.Fatalf("completion script missing %q command", command)
			}
		}
	}
}

func hasResult(results []searchResult, kind, name string) bool {
	for _, result := range results {
		if result.Kind == kind && result.Name == name {
			return true
		}
	}
	return false
}

package graph

import (
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func fixture() *tailnet.Tailnet {
	return &tailnet.Tailnet{
		Name: "test-net",
		Users: []*tailnet.User{
			{LoginName: "alice@example.com"},
			{LoginName: "bob@example.com"},
		},
		Devices: []*tailnet.Device{
			{Hostname: "web-1", Tags: []string{"tag:prod"}, Owner: ""},
			{Hostname: "db-1", Tags: []string{"tag:prod"}, Owner: ""},
		},
		Groups: map[string][]string{
			"group:eng": {"alice@example.com", "bob@example.com"},
		},
		TagOwners: map[string][]string{
			"tag:prod": {"group:eng"},
		},
		Grants: []*tailnet.Grant{
			{
				Sources:      []string{"group:eng", "tag:ci"},
				Destinations: []string{"tag:prod"},
				IP:           []string{"tcp:443", "tcp:5432"},
			},
			{
				Sources:      []string{"alice@example.com"},
				Destinations: []string{"db-1", "*"},
				Legacy:       true,
			},
		},
	}
}

func TestMermaidHeaderAndNodes(t *testing.T) {
	out := Mermaid(fixture())
	if !strings.HasPrefix(out, "flowchart LR\n") {
		t.Fatalf("Mermaid output should start with \"flowchart LR\", got:\n%s", out)
	}
	for _, want := range []string{
		`"group:eng"`,
		`"tag:prod"`,
		`"alice@example.com"`,
		`"db-1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected node label %s in output:\n%s", want, out)
		}
	}
}

func TestMermaidEdges(t *testing.T) {
	out := Mermaid(fixture())
	var edgeLines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "-->") {
			edgeLines = append(edgeLines, line)
		}
	}
	if len(edgeLines) == 0 {
		t.Fatalf("no edge lines in output:\n%s", out)
	}
	foundPort := false
	foundLegacy := false
	for _, l := range edgeLines {
		if strings.Contains(l, "tcp:443") {
			foundPort = true
		}
		if strings.Contains(l, "[legacy]") && strings.Contains(l, "(all)") {
			foundLegacy = true
		}
	}
	if !foundPort {
		t.Errorf("expected an edge labeled tcp:443 in output:\n%s", out)
	}
	if !foundLegacy {
		t.Errorf("expected a legacy edge labeled (all) [legacy] in output:\n%s", out)
	}
	if !strings.Contains(out, "linkStyle") {
		t.Errorf("expected dashed linkStyle for legacy edges:\n%s", out)
	}
}

func TestDOT(t *testing.T) {
	out := DOT(fixture())
	if !strings.HasPrefix(out, "digraph taildoc {") {
		t.Fatalf("DOT output should start with digraph, got:\n%s", out)
	}
	if !strings.Contains(out, "->") {
		t.Errorf("expected -> edges in output:\n%s", out)
	}
	if !strings.Contains(out, "[shape=folder]") {
		t.Errorf("expected group folder shape:\n%s", out)
	}
	if !strings.Contains(out, "style=dashed") {
		t.Errorf("expected dashed style for legacy grants:\n%s", out)
	}
}

func TestDeterminism(t *testing.T) {
	for _, fn := range []func(*tailnet.Tailnet) string{Mermaid, DOT} {
		a := fn(fixture())
		b := fn(fixture())
		if a != b {
			t.Errorf("%T output not deterministic:\n--- first ---\n%s\n--- second ---\n%s", fn, a, b)
		}
	}
}

func TestEscapeWeirdHostname(t *testing.T) {
	fx := fixture()
	fx.Devices = append(fx.Devices, &tailnet.Device{Hostname: `we"ird\$(rm -rf)`})
	fx.Grants[0].Destinations = append(fx.Grants[0].Destinations, `we"ird\$(rm -rf)`)

	mm := Mermaid(fx)
	if !strings.Contains(mm, `d6["we\"ird\\$(rm -rf)"]`) {
		t.Errorf("expected escaped quotes around weird hostname in mermaid:\n%s", mm)
	}
	dot := DOT(fx)
	if !strings.Contains(dot, `"we\"ird\\$(rm -rf)"`) {
		t.Errorf("expected properly quoted/escaped weird hostname in dot:\n%s", dot)
	}
}

func TestEdgesSorted(t *testing.T) {
	edges := Edges(fixture())
	if len(edges) == 0 {
		t.Fatal("expected edges")
	}
	for i := 1; i < len(edges); i++ {
		prev, cur := edges[i-1], edges[i]
		if prev.Src > cur.Src ||
			(prev.Src == cur.Src && prev.Dst > cur.Dst) ||
			(prev.Src == cur.Src && prev.Dst == cur.Dst && prev.Label > cur.Label) {
			t.Fatalf("edges not sorted at %d: %+v then %+v", i, prev, cur)
		}
	}
}

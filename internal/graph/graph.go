// Package graph renders tailnet grant relationships as dependency graphs
// in Mermaid flowchart and Graphviz DOT formats.
package graph

import (
	"sort"
	"strings"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Edge is a single directed access relationship between two policy selectors.
type Edge struct {
	Src    string
	Dst    string
	Label  string // joined IP ports, or "(all)"
	Legacy bool   // true if derived from a legacy ACL entry
}

// Edges enumerates one edge per (source, destination) pair across all grants,
// sorted deterministically by Src, Dst, Label.
func Edges(t *tailnet.Tailnet) []Edge {
	var out []Edge
	for _, g := range t.Grants {
		label := strings.Join(g.IP, ", ")
		if label == "" {
			label = "(all)"
		}
		for _, src := range g.Sources {
			for _, dst := range g.Destinations {
				out = append(out, Edge{Src: src, Dst: dst, Label: label, Legacy: g.Legacy})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src < out[j].Src
		}
		if out[i].Dst != out[j].Dst {
			return out[i].Dst < out[j].Dst
		}
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		return !out[i].Legacy && out[j].Legacy
	})
	return out
}

type nodeKind int

const (
	kindUser nodeKind = iota
	kindGroup
	kindTag
	kindDevice
	kindWildcard
)

func classify(t *tailnet.Tailnet, name string) nodeKind {
	switch {
	case name == "*":
		return kindWildcard
	case strings.HasPrefix(name, "group:"):
		return kindGroup
	case strings.HasPrefix(name, "tag:"):
		return kindTag
	case t.FindDevice(name) != nil:
		return kindDevice
	default:
		return kindUser
	}
}

// nodes returns the deduplicated, sorted set of selector names referenced by
// the given edges.
func nodes(t *tailnet.Tailnet, edges []Edge) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, e := range edges {
		add(e.Src)
		add(e.Dst)
	}
	sort.Strings(out)
	return out
}

// escapeLabel escapes a string for inclusion inside a double-quoted label in
// both Mermaid and DOT.
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ")
	return r.Replace(s)
}

// mermaidID maps a selector to a stable Mermaid-safe node identifier.
func mermaidID(kind nodeKind, index int) string {
	prefixes := map[nodeKind]string{
		kindUser:     "u",
		kindGroup:    "g",
		kindTag:      "t",
		kindDevice:   "d",
		kindWildcard: "w",
	}
	return prefixes[kind] + itoa(index)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// Mermaid renders the grant relationships as a Mermaid "flowchart LR".
// Users are rounded nodes, groups and tags are stadium nodes, devices are
// rectangles. Legacy ACL edges get a "[legacy]" label suffix and dashed styling.
func Mermaid(t *tailnet.Tailnet) string {
	edges := Edges(t)
	names := nodes(t, edges)

	ids := make(map[string]string, len(names))
	var b strings.Builder
	b.WriteString("flowchart LR\n")

	var legacyLinks []int
	for i, name := range names {
		kind := classify(t, name)
		id := mermaidID(kind, i)
		ids[name] = id
		label := escapeLabel(name)
		switch kind {
		case kindUser:
			b.WriteString("    " + id + "(\"" + label + "\")\n")
		case kindGroup, kindTag:
			b.WriteString("    " + id + "([\"" + label + "\"])\n")
		case kindDevice:
			b.WriteString("    " + id + "[\"" + label + "\"]\n")
		case kindWildcard:
			b.WriteString("    " + id + "((\"*\"))\n")
		}
	}

	for i, e := range edges {
		srcID, dstID := ids[e.Src], ids[e.Dst]
		label := escapeLabel(e.Label)
		if e.Legacy {
			label += " [legacy]"
			legacyLinks = append(legacyLinks, i)
		}
		b.WriteString("    " + srcID + " -->|\"" + label + "\"| " + dstID + "\n")
	}

	if len(legacyLinks) > 0 {
		parts := make([]string, 0, len(legacyLinks))
		for _, idx := range legacyLinks {
			parts = append(parts, itoa(idx))
		}
		b.WriteString("    linkStyle " + strings.Join(parts, ",") + " stroke-dasharray: 5 5\n")
	}

	return b.String()
}

// DOT renders the grant relationships as a Graphviz digraph. Users are
// ellipses, devices boxes, groups folders, tags tabs; legacy grants are dashed.
func DOT(t *tailnet.Tailnet) string {
	edges := Edges(t)
	names := nodes(t, edges)

	var b strings.Builder
	b.WriteString("digraph taildoc {\n")
	b.WriteString("    rankdir=LR;\n")

	shapes := map[nodeKind]string{
		kindUser:     "ellipse",
		kindDevice:   "box",
		kindGroup:    "folder",
		kindTag:      "tab",
		kindWildcard: "circle",
	}

	for _, name := range names {
		shape := shapes[classify(t, name)]
		b.WriteString("    \"" + escapeLabel(name) + "\" [shape=" + shape + "];\n")
	}

	for _, e := range edges {
		line := "    \"" + escapeLabel(e.Src) + "\" -> \"" + escapeLabel(e.Dst) + "\" [label=\"" + escapeLabel(e.Label) + "\""
		if e.Legacy {
			line += ", style=dashed"
		}
		line += "];\n"
		b.WriteString(line)
	}

	b.WriteString("}\n")
	return b.String()
}

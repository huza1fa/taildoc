// Package diff compares two tailnet snapshots and reports what changed.
package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Change describes a single difference between two snapshots.
// Kind is one of "added", "removed", or "changed".
type Change struct {
	Kind   string
	What   string
	Detail string
}

// Diff compares oldT against newT. Changes are ordered: added first, then
// removed, then changed; within each group sorted by What.
func Diff(oldT, newT *tailnet.Tailnet) []Change {
	if oldT == nil && newT == nil {
		return nil
	}
	var changes []Change
	changes = append(changes, diffUsers(oldT, newT)...)
	changes = append(changes, diffDevices(oldT, newT)...)
	changes = append(changes, diffGrants(oldT, newT)...)
	changes = append(changes, diffGroups(oldT, newT)...)
	changes = append(changes, diffPolicyControls(oldT, newT)...)
	if len(changes) == 0 {
		return nil
	}
	sort.SliceStable(changes, func(i, j int) bool {
		ri, rj := kindRank(changes[i].Kind), kindRank(changes[j].Kind)
		if ri != rj {
			return ri < rj
		}
		return changes[i].What < changes[j].What
	})
	return changes
}

func kindRank(k string) int {
	switch k {
	case "added":
		return 0
	case "removed":
		return 1
	default:
		return 2
	}
}

func diffUsers(oldT, newT *tailnet.Tailnet) []Change {
	oldIdx := make(map[string]*tailnet.User)
	if oldT != nil {
		for _, u := range oldT.Users {
			if u == nil || u.LoginName == "" {
				continue
			}
			oldIdx[u.LoginName] = u
		}
	}
	newIdx := make(map[string]*tailnet.User)
	if newT != nil {
		for _, u := range newT.Users {
			if u == nil || u.LoginName == "" {
				continue
			}
			newIdx[u.LoginName] = u
		}
	}
	var changes []Change
	for login := range newIdx {
		if _, ok := oldIdx[login]; !ok {
			changes = append(changes, Change{Kind: "added", What: "user " + login})
		}
	}
	for login := range oldIdx {
		if _, ok := newIdx[login]; !ok {
			changes = append(changes, Change{Kind: "removed", What: "user " + login})
		}
	}
	return changes
}

func diffDevices(oldT, newT *tailnet.Tailnet) []Change {
	oldIdx := make(map[string]*tailnet.Device)
	if oldT != nil {
		for _, d := range oldT.Devices {
			if d == nil {
				continue
			}
			oldIdx[deviceKey(d)] = d
		}
	}
	newIdx := make(map[string]*tailnet.Device)
	if newT != nil {
		for _, d := range newT.Devices {
			if d == nil {
				continue
			}
			newIdx[deviceKey(d)] = d
		}
	}
	var changes []Change
	for id, nd := range newIdx {
		od, ok := oldIdx[id]
		if !ok {
			changes = append(changes, Change{Kind: "added", What: deviceWhat(nd)})
			continue
		}
		var fields []string
		if !equalSet(od.Tags, nd.Tags) {
			fields = append(fields, fmt.Sprintf("tags %s -> %s", joinSorted(od.Tags), joinSorted(nd.Tags)))
		}
		if od.Owner != nd.Owner {
			fields = append(fields, fmt.Sprintf("owner %q -> %q", od.Owner, nd.Owner))
		}
		if !equalSet(od.AdvertisedRoutes, nd.AdvertisedRoutes) {
			fields = append(fields, fmt.Sprintf("advertised routes %s -> %s", joinSorted(od.AdvertisedRoutes), joinSorted(nd.AdvertisedRoutes)))
		}
		if !equalSet(od.EnabledRoutes, nd.EnabledRoutes) {
			fields = append(fields, fmt.Sprintf("enabled routes %s -> %s", joinSorted(od.EnabledRoutes), joinSorted(nd.EnabledRoutes)))
		}
		if od.Online != nd.Online {
			fields = append(fields, fmt.Sprintf("online %t -> %t", od.Online, nd.Online))
		}
		if od.Authorized != nd.Authorized {
			fields = append(fields, fmt.Sprintf("authorized %t -> %t", od.Authorized, nd.Authorized))
		}
		if len(fields) > 0 {
			changes = append(changes, Change{
				Kind:   "changed",
				What:   deviceWhat(nd),
				Detail: strings.Join(fields, "; "),
			})
		}
	}
	for id, od := range oldIdx {
		if _, ok := newIdx[id]; !ok {
			changes = append(changes, Change{Kind: "removed", What: deviceWhat(od)})
		}
	}
	return changes
}

func deviceWhat(d *tailnet.Device) string {
	if d == nil {
		return "device (unknown)"
	}
	name := d.Hostname
	if name == "" {
		name = d.Name
	}
	if name == "" {
		name = "(unknown)"
	}
	if d.ID == "" {
		return fmt.Sprintf("device %s", name)
	}
	return fmt.Sprintf("device %s (%s)", name, d.ID)
}

func deviceKey(d *tailnet.Device) string {
	if d.ID != "" {
		return d.ID
	}
	if d.Hostname != "" {
		return "hostname:" + d.Hostname
	}
	if d.Name != "" {
		return "name:" + d.Name
	}
	return fmt.Sprintf("addr:%s", strings.Join(d.Addresses, ","))
}

func grantCanonical(g *tailnet.Grant) string {
	if g == nil {
		return "<nil>"
	}
	parts := []string{
		joinSorted(g.Sources),
		joinSorted(g.Destinations),
		joinSorted(g.IP),
		canonicalJSON(g.App),
		joinSorted(g.SrcPosture),
		joinSorted(g.Via),
		fmt.Sprint(g.Legacy),
	}
	return strings.Join(parts, "|")
}

func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unserializable>"
	}
	return string(b)
}

func grantDetail(legacy bool) string {
	if legacy {
		return "legacy acl"
	}
	return "grant"
}

func diffGrants(oldT, newT *tailnet.Tailnet) []Change {
	countAndLegacy := func(t *tailnet.Tailnet) (map[string]int, map[string]bool) {
		m := make(map[string]int)
		leg := make(map[string]bool)
		if t == nil {
			return m, leg
		}
		for _, g := range t.Grants {
			if g == nil {
				continue
			}
			canon := grantCanonical(g)
			m[canon]++
			leg[canon] = g.Legacy
		}
		return m, leg
	}
	oldCounts, oldLegacy := countAndLegacy(oldT)
	newCounts, newLegacy := countAndLegacy(newT)
	var changes []Change
	for canon, n := range newCounts {
		added := n - oldCounts[canon]
		for i := 0; i < added; i++ {
			changes = append(changes, Change{
				Kind:   "added",
				What:   "grant " + canon,
				Detail: grantDetail(newLegacy[canon]),
			})
		}
	}
	for canon, n := range oldCounts {
		removed := n - newCounts[canon]
		for i := 0; i < removed; i++ {
			changes = append(changes, Change{
				Kind:   "removed",
				What:   "grant " + canon,
				Detail: grantDetail(oldLegacy[canon]),
			})
		}
	}
	return changes
}

func diffGroups(oldT, newT *tailnet.Tailnet) []Change {
	groups := func(t *tailnet.Tailnet) map[string][]string {
		if t == nil {
			return nil
		}
		return t.Groups
	}
	oldG, newG := groups(oldT), groups(newT)
	names := make(map[string]bool)
	for g := range oldG {
		names[g] = true
	}
	for g := range newG {
		names[g] = true
	}
	sorted := make([]string, 0, len(names))
	for g := range names {
		sorted = append(sorted, g)
	}
	sort.Strings(sorted)

	var changes []Change
	for _, g := range sorted {
		om, nm := oldG[g], newG[g]
		oldSet := toSet(om)
		newSet := toSet(nm)
		var added, removed []string
		for m := range newSet {
			if !oldSet[m] {
				added = append(added, m)
			}
		}
		for m := range oldSet {
			if !newSet[m] {
				removed = append(removed, m)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		var parts []string
		if len(added) > 0 {
			parts = append(parts, "added "+strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			parts = append(parts, "removed "+strings.Join(removed, ", "))
		}
		if len(parts) > 0 {
			changes = append(changes, Change{
				Kind:   "changed",
				What:   "group " + g,
				Detail: strings.Join(parts, "; "),
			})
		}
	}
	return changes
}

func diffPolicyControls(oldT, newT *tailnet.Tailnet) []Change {
	controls := func(t *tailnet.Tailnet) (*tailnet.Tailnet, bool) {
		return t, t != nil
	}
	old, oldOK := controls(oldT)
	new, newOK := controls(newT)
	if !oldOK {
		old = &tailnet.Tailnet{}
	}
	if !newOK {
		new = &tailnet.Tailnet{}
	}
	changes := diffStringMap("host alias", old.Hosts, new.Hosts)
	changes = append(changes, diffMemberMaps("tag owner", old.TagOwners, new.TagOwners)...)
	changes = append(changes, diffMemberMaps("posture", old.Postures, new.Postures)...)
	changes = append(changes, diffMemberMaps("auto approver route", old.AutoApprovers.Routes, new.AutoApprovers.Routes)...)
	changes = append(changes, diffMemberMaps("auto approver service", old.AutoApprovers.Services, new.AutoApprovers.Services)...)
	if !equalSet(old.AutoApprovers.ExitNode, new.AutoApprovers.ExitNode) {
		changes = append(changes, Change{Kind: "changed", What: "auto approver exit nodes", Detail: fmt.Sprintf("%s -> %s", joinSorted(old.AutoApprovers.ExitNode), joinSorted(new.AutoApprovers.ExitNode))})
	}
	if old.HasAccessRules != new.HasAccessRules {
		changes = append(changes, Change{Kind: "changed", What: "access policy mode", Detail: fmt.Sprintf("explicit rules %t -> %t", old.HasAccessRules, new.HasAccessRules)})
	}
	if !equalSet(old.DefaultSrcPosture, new.DefaultSrcPosture) {
		changes = append(changes, Change{Kind: "changed", What: "default source posture", Detail: fmt.Sprintf("%s -> %s", joinSorted(old.DefaultSrcPosture), joinSorted(new.DefaultSrcPosture))})
	}
	return changes
}

func diffStringMap(kind string, old, new map[string]string) []Change {
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range new {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var changes []Change
	for _, k := range sorted {
		ov, oldOK := old[k]
		nv, newOK := new[k]
		what := kind + " " + k
		switch {
		case !oldOK:
			changes = append(changes, Change{Kind: "added", What: what, Detail: nv})
		case !newOK:
			changes = append(changes, Change{Kind: "removed", What: what, Detail: ov})
		case ov != nv:
			changes = append(changes, Change{Kind: "changed", What: what, Detail: fmt.Sprintf("%s -> %s", ov, nv)})
		}
	}
	return changes
}

func diffMemberMaps(kind string, old, new map[string][]string) []Change {
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range new {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var changes []Change
	for _, k := range sorted {
		ov, oldOK := old[k]
		nv, newOK := new[k]
		what := kind + " " + k
		switch {
		case !oldOK:
			changes = append(changes, Change{Kind: "added", What: what, Detail: joinSorted(nv)})
		case !newOK:
			changes = append(changes, Change{Kind: "removed", What: what, Detail: joinSorted(ov)})
		case !equalSet(ov, nv):
			changes = append(changes, Change{Kind: "changed", What: what, Detail: fmt.Sprintf("%s -> %s", joinSorted(ov), joinSorted(nv))})
		}
	}
	return changes
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		if counts[v] == 0 {
			return false
		}
		counts[v]--
	}
	return true
}

func joinSorted(ss []string) string {
	c := append([]string(nil), ss...)
	sort.Strings(c)
	return "[" + strings.Join(c, ", ") + "]"
}

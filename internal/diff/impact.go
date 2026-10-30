package diff

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// ImpactOptions bounds an exact comparison of packet policy for collected
// devices. Ports are partitioned at rule boundaries rather than sampled, and
// MaxEvaluations counts distinct policy evaluations, not device pairs.
type ImpactOptions struct {
	Source, Destination string
	Port                string
	Protocols           []string
	MaxEvaluations      int
}
type AccessChange struct {
	Kind        string `json:"kind"` // gained, lost, or uncertain
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Ports       string `json:"ports"`
	Before      string `json:"before"`
	After       string `json:"after"`
}
type ImpactReport struct {
	Scope              string         `json:"scope"`
	Evaluations        int            `json:"evaluations"`
	UnknownEvaluations int            `json:"unknown_evaluations"`
	Changes            []AccessChange `json:"changes"`
}

func AccessImpact(ctx context.Context, oldT, newT *tailnet.Tailnet, opts ImpactOptions) (ImpactReport, error) {
	report := ImpactReport{Scope: "Collected device pairs; packet policy only, excluding service, subnet destination, and runtime connectivity analysis.", Changes: []AccessChange{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if oldT == nil || newT == nil {
		return report, fmt.Errorf("access impact requires two snapshots")
	}
	if len(opts.Protocols) == 0 {
		opts.Protocols = []string{"tcp", "udp"}
	}
	protocols := make([]string, 0, len(opts.Protocols))
	seenProtocols := map[string]bool{}
	for _, p := range opts.Protocols {
		if !seenProtocols[p] {
			seenProtocols[p] = true
			protocols = append(protocols, p)
		}
	}
	opts.Protocols = protocols
	for _, p := range opts.Protocols {
		if p != "tcp" && p != "udp" && p != "sctp" {
			return report, fmt.Errorf("impact protocol must be tcp, udp, or sctp")
		}
	}
	if opts.MaxEvaluations <= 0 {
		opts.MaxEvaluations = 1000000
	}
	intervals := impactIntervals(oldT, newT)
	if opts.Port != "" {
		ranges := policy.PortRanges(opts.Port)
		if len(ranges) != 1 || ranges[0][0] != ranges[0][1] {
			return report, fmt.Errorf("impact port must be a number from 0 to 65535")
		}
		intervals = ranges
	}
	oldIdx, err := deviceIndex(oldT)
	if err != nil {
		return report, err
	}
	newIdx, err := deviceIndex(newT)
	if err != nil {
		return report, err
	}
	keys := map[string]bool{}
	for k := range oldIdx {
		keys[k] = true
	}
	for k := range newIdx {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	matches := func(k, ref string) bool {
		if ref == "" {
			return true
		}
		for _, d := range []*tailnet.Device{oldIdx[k], newIdx[k]} {
			if d != nil && (d.ID == ref || d.Hostname == ref || d.Name == ref) {
				return true
			}
			if d != nil {
				for _, ip := range d.Addresses {
					if ip == ref {
						return true
					}
				}
			}
		}
		return false
	}
	var sources, destinations []string
	for _, k := range ordered {
		if matches(k, opts.Source) {
			sources = append(sources, k)
		}
		if matches(k, opts.Destination) {
			destinations = append(destinations, k)
		}
	}
	if opts.Source != "" && len(sources) == 0 {
		return report, fmt.Errorf("no impact source matches %q", opts.Source)
	}
	if opts.Destination != "" && len(destinations) == 0 {
		return report, fmt.Errorf("no impact destination matches %q", opts.Destination)
	}
	// Devices with the same policy identity get the same answer, so the budget
	// counts distinct evaluations and results are shared between device pairs.
	oldClass := accessClasses(oldT, newT, oldIdx)
	newClass := accessClasses(oldT, newT, newIdx)
	// Reject expensive scopes before producing any partial or misleading output.
	cost := (classPairs(oldClass, sources, destinations) + classPairs(newClass, sources, destinations)) * int64(len(intervals)) * int64(len(opts.Protocols))
	if cost > int64(opts.MaxEvaluations) {
		return report, fmt.Errorf("impact needs %d evaluations (limit %d); narrow with --source, --destination, or --port", cost, opts.MaxEvaluations)
	}
	oldStates, newStates := map[stateKey]string{}, map[stateKey]string{}
	hostnames := map[string]map[string]bool{}
	for _, idx := range []map[string]*tailnet.Device{oldIdx, newIdx} {
		for k, d := range idx {
			if hostnames[d.Hostname] == nil {
				hostnames[d.Hostname] = map[string]bool{}
			}
			hostnames[d.Hostname][k] = true
		}
	}
	name := func(k string) string {
		d := newIdx[k]
		if d == nil {
			d = oldIdx[k]
		}
		if d.Hostname != "" && (len(hostnames[d.Hostname]) == 1 || d.Name == "") {
			return d.Hostname
		}
		if d.Name != "" {
			return d.Name
		}
		return k
	}
	for _, s := range sources {
		for _, d := range destinations {
			if s == d {
				continue
			}
			for _, proto := range opts.Protocols {
				last := -1
				lastEnd := -1
				for _, r := range intervals {
					if err := ctx.Err(); err != nil {
						return report, err
					}
					before := cachedState(oldStates, oldClass, oldT, oldIdx, s, d, r[0], proto)
					after := cachedState(newStates, newClass, newT, newIdx, s, d, r[0], proto)
					report.Evaluations += 2
					if before == "unknown" {
						report.UnknownEvaluations++
					}
					if after == "unknown" {
						report.UnknownEvaluations++
					}
					if before == after {
						last = -1
						continue
					}
					kind := "uncertain"
					if before != "unknown" && after != "unknown" {
						if after == "allowed" {
							kind = "gained"
						} else if before == "allowed" {
							kind = "lost"
						} else {
							continue
						}
					}
					if last >= 0 && lastEnd+1 == r[0] && report.Changes[last].Before == before && report.Changes[last].After == after {
						start, _, _ := strings.Cut(report.Changes[last].Ports, "-")
						report.Changes[last].Ports = start + "-" + strconv.Itoa(r[1])
						lastEnd = r[1]
						continue
					}
					ports := strconv.Itoa(r[0])
					if r[0] != r[1] {
						ports += "-" + strconv.Itoa(r[1])
					}
					report.Changes = append(report.Changes, AccessChange{kind, name(s), name(d), proto, ports, before, after})
					last = len(report.Changes) - 1
					lastEnd = r[1]
				}
			}
		}
	}
	return report, nil
}
func deviceIndex(t *tailnet.Tailnet) (map[string]*tailnet.Device, error) {
	idx := map[string]*tailnet.Device{}
	for _, d := range t.Devices {
		if d != nil {
			key := deviceKey(d)
			if _, exists := idx[key]; exists {
				return nil, fmt.Errorf("duplicate device identity %q in snapshot; cannot compare access reliably", key)
			}
			idx[key] = d
		}
	}
	return idx, nil
}
func accessState(t *tailnet.Tailnet, src, dst *tailnet.Device, port int, proto string) string {
	if src == nil || dst == nil {
		return "absent"
	}
	r := policy.Evaluate(t, policy.Between(src, dst, strconv.Itoa(port), proto))
	if r.Allowed {
		return "allowed"
	}
	if r.Indeterminate {
		return "unknown"
	}
	return "denied"
}

type stateKey struct {
	src, dst, port int
	proto          string
}

func cachedState(cache map[stateKey]string, class map[string]int, t *tailnet.Tailnet, idx map[string]*tailnet.Device, src, dst string, port int, proto string) string {
	if idx[src] == nil || idx[dst] == nil {
		return "absent"
	}
	key := stateKey{class[src], class[dst], port, proto}
	state, ok := cache[key]
	if !ok {
		state = accessState(t, idx[src], idx[dst], port, proto)
		cache[key] = state
	}
	return state
}

// accessClasses numbers devices by everything Evaluate reads from them. Both
// snapshots decide whether addresses count, since either may be the one with
// an IP selector; a device with no user or tag is always matched by address.
func accessClasses(oldT, newT *tailnet.Tailnet, idx map[string]*tailnet.Device) map[string]int {
	byAddress := usesAddressSelectors(oldT) || usesAddressSelectors(newT)
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ids := map[string]int{}
	class := make(map[string]int, len(idx))
	for _, k := range keys {
		d := idx[k]
		tags := append([]string(nil), d.Tags...)
		sort.Strings(tags)
		identity := d.Owner + "\x00" + strings.Join(tags, "\x00")
		if len(tags) == 0 {
			identity = "user\x00" + identity
		}
		if byAddress || (d.Owner == "" && len(tags) == 0) {
			addresses := append([]string(nil), d.Addresses...)
			sort.Strings(addresses)
			identity += "\x01" + strings.Join(addresses, "\x00")
		}
		id, ok := ids[identity]
		if !ok {
			id = len(ids)
			ids[identity] = id
		}
		class[k] = id
	}
	return class
}

// usesAddressSelectors reports whether any rule selects by something other than
// identity, which would make two devices with one identity differ.
func usesAddressSelectors(t *tailnet.Tailnet) bool {
	symbolic := func(sel string) bool {
		return sel == "*" || strings.Contains(sel, "@") || strings.HasPrefix(sel, "tag:") ||
			strings.HasPrefix(sel, "group:") || strings.HasPrefix(sel, "autogroup:")
	}
	for _, g := range t.Grants {
		if g == nil {
			continue
		}
		for _, sel := range g.Sources {
			if !symbolic(sel) {
				return true
			}
		}
		for _, dst := range g.Destinations {
			host, _, ok := policy.SplitDestination(dst)
			if !ok || !symbolic(host) {
				return true
			}
		}
	}
	return false
}

func classPairs(class map[string]int, sources, destinations []string) int64 {
	distinct := func(keys []string) int64 {
		seen := map[int]bool{}
		for _, k := range keys {
			if id, ok := class[k]; ok {
				seen[id] = true
			}
		}
		return int64(len(seen))
	}
	return distinct(sources) * distinct(destinations)
}

func impactIntervals(ts ...*tailnet.Tailnet) [][2]int {
	bounds := map[int]bool{0: true, 65536: true}
	add := func(spec string) {
		for _, r := range policy.PortRanges(spec) {
			bounds[r[0]] = true
			bounds[r[1]+1] = true
		}
	}
	for _, t := range ts {
		for _, g := range t.Grants {
			if g == nil {
				continue
			}
			for _, dst := range g.Destinations {
				_, p, ok := policy.SplitDestination(dst)
				if ok {
					add(p)
				}
			}
			for _, ip := range g.IP {
				_, p, ok := strings.Cut(ip, ":")
				if !ok {
					p = ip
				}
				add(p)
			}
		}
	}
	ordered := make([]int, 0, len(bounds))
	for b := range bounds {
		ordered = append(ordered, b)
	}
	sort.Ints(ordered)
	intervals := make([][2]int, 0, len(ordered)-1)
	for i := 0; i < len(ordered)-1; i++ {
		intervals = append(intervals, [2]int{ordered[i], ordered[i+1] - 1})
	}
	return intervals
}

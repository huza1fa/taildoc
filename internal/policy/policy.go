// Package policy evaluates the supported subset of Tailscale policy locally.
// Unsupported selectors and conditions produce uncertainty, never a guessed denial.
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

type Request struct {
	SourceLogin string
	SourceTags  []string
	SourceIPs   []string
	DestTags    []string
	DestIPs     []string
	DestOwner   string
	Port        string // empty or * asks whether any port is permitted
	Proto       string // empty asks whether any protocol is permitted
}

type Match struct {
	Grant *tailnet.Grant
	Chain []string
}
type Unsupported struct {
	Selector string
	Reason   string
}
type Result struct {
	Allowed        bool
	Indeterminate  bool
	DefaultAllowed bool
	Matches        []Match
	Unsupported    []Unsupported
}

// Between builds a packet-policy request. Tags replace a device's user identity.
func Between(src, dst *tailnet.Device, port, proto string) Request {
	r := Request{Port: port, Proto: proto}
	if src != nil {
		r.SourceTags, r.SourceIPs = src.Tags, src.Addresses
		if len(src.Tags) == 0 {
			r.SourceLogin = src.Owner
		}
	}
	if dst != nil {
		r.DestTags, r.DestIPs = dst.Tags, dst.Addresses
		if len(dst.Tags) == 0 {
			r.DestOwner = dst.Owner
		}
	}
	return r
}

func Evaluate(t *tailnet.Tailnet, req Request) Result {
	if t == nil {
		return Result{Indeterminate: true, Unsupported: []Unsupported{{"snapshot", "no snapshot available"}}}
	}
	if !t.HasAccessRules && len(t.Grants) == 0 {
		if len(t.DefaultSrcPosture) > 0 {
			return Result{Indeterminate: true, Unsupported: []Unsupported{{"defaultSrcPosture", "posture evaluation is not supported"}}}
		}
		return Result{Allowed: true, DefaultAllowed: true}
	}
	var res Result
	for _, g := range t.Grants {
		if g == nil {
			continue
		}
		src, srcKnown, srcNotes := matchAny(t, g.Sources, req, true)
		if !src && srcKnown {
			continue
		}
		for _, dst := range g.Destinations {
			host, port, ok := splitDst(dst)
			if !ok {
				res.Unsupported = append(res.Unsupported, Unsupported{dst, "unrecognized destination format"})
				res.Indeterminate = true
				continue
			}
			dm, dk, dn := matchSelector(t, host, req, false, map[string]bool{})
			if !dm && dk {
				continue
			}
			// App capabilities do not themselves grant packet access. A grant may
			// independently provide both network and application permissions.
			if !g.Legacy && len(g.IP) == 0 {
				if len(g.App) > 0 {
					continue
				}
				res.Indeterminate = true
				res.Unsupported = append(res.Unsupported, Unsupported{"ip", "grant has no network or application permissions"})
				continue
			}
			if g.Legacy {
				gp := g.Protocol
				if gp == "" && req.Proto != "" && normalizeProto(req.Proto) != "tcp" && normalizeProto(req.Proto) != "udp" && normalizeProto(req.Proto) != "icmp" {
					continue
				}
				if gp != "" && req.Proto != "" && normalizeProto(req.Proto) != "icmp" && normalizeProto(gp) != normalizeProto(req.Proto) {
					continue
				}
			}
			validIP := true
			for _, entry := range g.IP {
				proto, spec, hasProto := strings.Cut(entry, ":")
				if !hasProto {
					spec = entry
				}
				if len(PortRanges(spec)) == 0 || (hasProto && proto != "*" && !ValidProtocol(proto)) {
					validIP = false
				}
			}
			if !validIP {
				res.Indeterminate = true
				res.Unsupported = append(res.Unsupported, Unsupported{"ip " + strings.Join(g.IP, ","), "network expression is not supported"})
				continue
			}
			want, proto := req.Port, req.Proto
			// ACLs implicitly allow ICMP whenever they permit traffic for a pair.
			// ICMP has no destination port; inspect whether any ACL port is allowed.
			if g.Legacy && normalizeProto(proto) == "icmp" {
				want, proto = "", ""
			}
			entries := g.IP
			if g.Legacy && len(entries) == 0 {
				entries = []string{"*:*"}
			}
			pm, why := matchPorts(entries, port, want, proto)
			if !pm {
				continue
			}
			notes := append(append([]Unsupported{}, srcNotes...), dn...)
			posture := g.SrcPosture
			if posture == nil {
				posture = t.DefaultSrcPosture
			}
			if len(posture) > 0 {
				notes = append(notes, Unsupported{"srcPosture " + strings.Join(posture, ","), "posture evaluation is not supported"})
			}
			if len(g.Via) > 0 {
				notes = append(notes, Unsupported{"via " + strings.Join(g.Via, ","), "routing constraints cannot be evaluated locally"})
			}
			if !srcKnown || !dk || len(notes) > 0 {
				res.Indeterminate = true
				res.Unsupported = append(res.Unsupported, notes...)
				continue
			}
			res.Matches = append(res.Matches, Match{g, []string{
				fmt.Sprintf("source %q matches a source selector", describeSource(req)),
				fmt.Sprintf("destination matches %s", dst),
				"ports allow " + why,
			}})
			break
		}
	}
	res.Allowed = len(res.Matches) > 0
	// A certain allow wins over uncertain alternative paths.
	if res.Allowed {
		res.Indeterminate = false
	}
	return res
}

func SourceSelectors(t *tailnet.Tailnet, req Request) []string {
	sels := []string{"*"}
	if len(req.SourceTags) > 0 {
		return append(append(sels, "autogroup:tagged"), req.SourceTags...)
	}
	if req.SourceLogin != "" {
		sels = append(sels, req.SourceLogin)
		sels = append(sels, t.GroupsOfUser(req.SourceLogin)...)
		if u := t.FindUser(req.SourceLogin); u != nil {
			if u.Type != "shared" {
				sels = append(sels, "autogroup:member")
			}
			if u.Role != "" {
				sels = append(sels, "autogroup:"+u.Role)
			}
			if u.Role == "owner" {
				sels = append(sels, "autogroup:admin")
			}
		}
	}
	return sels
}

func matchAny(t *tailnet.Tailnet, selectors []string, req Request, source bool) (bool, bool, []Unsupported) {
	known := true
	var notes []Unsupported
	for _, sel := range selectors {
		match, k, n := matchSelector(t, sel, req, source, map[string]bool{})
		if match && k {
			return true, true, nil
		}
		if !k {
			known = false
			notes = append(notes, n...)
		}
	}
	return false, known, notes
}

func matchSelector(t *tailnet.Tailnet, sel string, req Request, source bool, visiting map[string]bool) (bool, bool, []Unsupported) {
	unknown := func(reason string) (bool, bool, []Unsupported) { return false, false, []Unsupported{{sel, reason}} }
	login, tags, ips := req.DestOwner, req.DestTags, req.DestIPs
	if source {
		login, tags, ips = req.SourceLogin, req.SourceTags, req.SourceIPs
	}
	switch {
	case sel == "*":
		// Wildcards cover tailnet devices and approved routes, not arbitrary
		// internet addresses. Abstract identity/tag queries have no concrete IP.
		if len(ips) == 0 || login != "" || len(tags) > 0 {
			return true, true, nil
		}
		for _, ip := range ips {
			for _, d := range t.Devices {
				if d == nil {
					continue
				}
				if contains(d.Addresses, ip) {
					return true, true, nil
				}
				for _, r := range d.EnabledRoutes {
					if ipMatches(r, ip) {
						return true, true, nil
					}
				}
			}
		}
		return false, true, nil
	case strings.HasPrefix(sel, "tag:"):
		return contains(tags, sel), true, nil
	case sel == "autogroup:self":
		if source {
			return unknown("autogroup:self is only supported as a destination")
		}
		return len(tags) == 0 && req.SourceLogin != "" && req.SourceLogin == login, true, nil
	case sel == "autogroup:tagged":
		return len(tags) > 0, true, nil
	case strings.HasPrefix(sel, "group:"):
		members, ok := t.Groups[sel]
		if !ok {
			return unknown("group definition is unavailable")
		}
		return len(tags) == 0 && contains(members, login), true, nil
	case strings.Contains(sel, "@") && !strings.Contains(sel, ":"):
		return len(tags) == 0 && login == sel, true, nil
	case strings.HasPrefix(sel, "autogroup:"):
		role := strings.TrimPrefix(sel, "autogroup:")
		switch role {
		case "member", "admin", "owner", "it-admin", "network-admin", "billing-admin", "auditor":
			if login == "" || len(tags) > 0 {
				return false, true, nil
			}
			u := t.FindUser(login)
			if u == nil {
				return unknown("user role is unavailable")
			}
			if role == "member" {
				return u.Type != "shared", true, nil
			}
			return u.Role == role || (role == "admin" && u.Role == "owner"), true, nil
		default:
			return unknown("autogroup selector is not supported")
		}
	case strings.HasPrefix(sel, "ipset:"):
		ranges, ok := t.IPSets[sel]
		if !ok {
			ranges, ok = t.IPSets[strings.TrimPrefix(sel, "ipset:")]
		}
		if !ok || visiting[sel] {
			return unknown("IP set is missing or cyclic")
		}
		visiting[sel] = true
		defer delete(visiting, sel)
		return matchIPSet(t, ranges, req, source, visiting)
	default:
		target := sel
		if alias, ok := t.Hosts[sel]; ok {
			target = alias
		}
		if !looksLikeIPOrCIDR(target) {
			return unknown("selector is not supported")
		}
		if len(ips) == 0 {
			return unknown("device IP addresses are unavailable")
		}
		for _, ip := range ips {
			if ipMatches(target, ip) {
				return true, true, nil
			}
		}
		return false, true, nil
	}
}

// matchIPSet applies members in order, so a later "remove" can undo an earlier
// "add". An unevaluable member only leaves the result unknown if it could
// change the outcome reached so far.
func matchIPSet(t *tailnet.Tailnet, members []string, req Request, source bool, visiting map[string]bool) (bool, bool, []Unsupported) {
	in, known := false, true
	var notes []Unsupported
	for _, member := range members {
		remove, target := parseIPSetMember(member)
		m, k, n := matchIPSetTarget(t, target, req, source, visiting)
		switch {
		case !k:
			notes = append(notes, n...)
			// Adding to a set already containing the address changes nothing,
			// and neither does removing from one that lacks it.
			if in == remove {
				known = false
			}
		case m:
			in, known = !remove, true
		}
	}
	if !known {
		return false, false, notes
	}
	return in, true, nil
}

func parseIPSetMember(member string) (remove bool, target string) {
	op, rest, ok := strings.Cut(strings.TrimSpace(member), " ")
	if ok && (op == "add" || op == "remove") {
		return op == "remove", strings.TrimSpace(rest)
	}
	return false, strings.TrimSpace(member)
}

func matchIPSetTarget(t *tailnet.Tailnet, target string, req Request, source bool, visiting map[string]bool) (bool, bool, []Unsupported) {
	if alias, ok := strings.CutPrefix(target, "host:"); ok {
		if _, defined := t.Hosts[alias]; !defined {
			return false, false, []Unsupported{{target, "host alias is not defined"}}
		}
		target = alias
	}
	if start, end, ok := strings.Cut(target, "-"); ok && looksLikeIPOrCIDR(start) && looksLikeIPOrCIDR(end) {
		ips := req.DestIPs
		if source {
			ips = req.SourceIPs
		}
		if len(ips) == 0 {
			return false, false, []Unsupported{{target, "device IP addresses are unavailable"}}
		}
		for _, ip := range ips {
			if ipInRange(ip, start, end) {
				return true, true, nil
			}
		}
		return false, true, nil
	}
	return matchSelector(t, target, req, source, visiting)
}

func ipInRange(ip, start, end string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	lo, err1 := netip.ParseAddr(start)
	hi, err2 := netip.ParseAddr(end)
	if err1 != nil || err2 != nil || addr.BitLen() != lo.BitLen() {
		return false
	}
	return addr.Compare(lo) >= 0 && addr.Compare(hi) <= 0
}

// matchPorts intersects destination ports with grant IP entries. Empty grant
// entries are used only by legacy ACLs; their ports remain in the destination.
func matchPorts(entries []string, dstPort, want, proto string) (bool, string) {
	if dstPort == "" {
		dstPort = "*"
	}
	if want != "" && want != "*" && !portInRange(dstPort, want) {
		return false, ""
	}
	if len(entries) == 0 {
		entries = []string{"*"}
	}
	for _, entry := range entries {
		p, spec, hasProto := strings.Cut(entry, ":")
		if !hasProto {
			p, spec = "", entry
		}
		if entry == "*" {
			hasProto, p = true, "*" // the same grant as "*:*": every protocol
		}
		if !hasProto && proto != "" {
			switch normalizeProto(proto) {
			case "tcp", "udp":
			case "icmp":
				if rangesOverlap(dstPort, spec) {
					return true, "ICMP implied by " + entry
				}
				continue
			default:
				continue
			}
		}
		if p != "" && p != "*" && proto != "" && normalizeProto(p) != normalizeProto(proto) {
			continue
		}
		if want == "" || want == "*" {
			if rangesOverlap(dstPort, spec) {
				return true, entry + " intersected with " + dstPort
			}
		} else if portInRange(spec, want) {
			return true, fmt.Sprintf("%s (requested %s)", entry, want)
		}
	}
	return false, ""
}

// PortRanges parses wildcard, comma-separated ports, and inclusive ranges.
// It is shared with access-impact analysis to examine whole intervals exactly.
func PortRanges(spec string) [][2]int {
	var out [][2]int
	for _, part := range strings.Split(spec, ",") {
		if part == "*" {
			out = append(out, [2]int{0, 65535})
			continue
		}
		lo, hi, rangeOK := strings.Cut(part, "-")
		if !rangeOK {
			hi = lo
		}
		a, e1 := strconv.Atoi(lo)
		b, e2 := strconv.Atoi(hi)
		if e1 != nil || e2 != nil || a < 0 || b > 65535 || a > b {
			return nil
		}
		out = append(out, [2]int{a, b})
	}
	return out
}
func portInRange(spec, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, r := range PortRanges(spec) {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}
func rangesOverlap(a, b string) bool {
	for _, x := range PortRanges(a) {
		for _, y := range PortRanges(b) {
			if x[0] <= y[1] && y[0] <= x[1] {
				return true
			}
		}
	}
	return false
}
func normalizeProto(p string) string {
	switch strings.ToLower(p) {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1", "58", "ipv6-icmp":
		return "icmp"
	case "132":
		return "sctp"
	case "2":
		return "igmp"
	case "4", "ip-in-ip":
		return "ipv4"
	case "8":
		return "egp"
	case "9":
		return "igp"
	case "47":
		return "gre"
	case "50":
		return "esp"
	case "51":
		return "ah"
	}
	return strings.ToLower(p)
}

// SplitDestination separates a selector from legacy destination ports.
func SplitDestination(dst string) (string, string, bool) { return splitDst(dst) }
func splitDst(dst string) (host, port string, ok bool) {
	if looksLikeIPOrCIDR(dst) {
		return dst, "*", true
	}
	if strings.HasPrefix(dst, "[") {
		end := strings.Index(dst, "]")
		if end > 0 && len(dst) > end+1 && dst[end+1] == ':' {
			p := dst[end+2:]
			return dst[1:end], p, len(PortRanges(p)) > 0
		}
		return dst, "", false
	}
	i := strings.LastIndex(dst, ":")
	if i < 0 {
		return dst, "*", dst != ""
	}
	if strings.Count(dst, ":") == 1 {
		switch dst[:i] {
		case "tag", "group", "autogroup", "ipset", "svc":
			// A numeric selector name (tag:22) is not a destination port.
			return dst, "*", true
		}
	}
	if p := dst[i+1:]; p != "" && (p[0] == '*' || (p[0] >= '0' && p[0] <= '9')) && len(PortRanges(p)) > 0 {
		return dst[:i], p, true
	}
	// A namespace separator is not a port separator.
	if strings.Count(dst, ":") == 1 {
		return dst, "*", true
	}
	return dst, "", false
}
func ipMatches(selector, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if prefix, err := netip.ParsePrefix(selector); err == nil {
		return prefix.Contains(addr)
	}
	sel, err := netip.ParseAddr(selector)
	return err == nil && sel == addr
}
func looksLikeIPOrCIDR(s string) bool {
	// Most destinations are symbolic selectors. Avoid constructing netip parse
	// errors for their namespace prefixes on every device/port evaluation.
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		for i := 0; i < colon; i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	} else if !strings.Contains(s, ".") {
		return false
	}
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
func describeSource(req Request) string {
	if req.SourceLogin != "" {
		return req.SourceLogin
	}
	return strings.Join(append(append([]string{}, req.SourceTags...), req.SourceIPs...), ", ")
}
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// ValidProtocol accepts supported IANA names or numbers. The evaluator treats
// numeric and named aliases equivalently.
func ValidProtocol(p string) bool {
	if n, err := strconv.Atoi(p); err == nil {
		return n >= 1 && n <= 255
	}
	switch strings.ToLower(p) {
	case "tcp", "udp", "icmp", "ipv6-icmp", "sctp", "igmp", "ipv4", "ip-in-ip", "egp", "igp", "gre", "esp", "ah":
		return true
	}
	return false
}

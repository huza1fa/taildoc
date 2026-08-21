// Package policy evaluates Tailscale grant semantics locally against a
// collected tailnet snapshot. This is a pragmatic subset of the full
// documented syntax; anything unsupported is reported as such rather than
// guessed at.
package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Request describes an access question: can the source reach the
// destination on port/proto?
type Request struct {
	SourceLogin string   // owning user's login (empty for tagged devices)
	SourceTags  []string // tags on the source device, if any
	DestTags    []string
	DestIPs     []string
	DestOwner   string
	Port        string // "" or "*" means any port
	Proto       string // "", "tcp", "udp", or numeric/IANA name; "" means any
}

// Match is one grant that allows the requested access.
type Match struct {
	Grant *tailnet.Grant
	Chain []string // human-readable chain: why this grant applies
}

// Unsupported records selectors Taildoc could not evaluate with certainty.
type Unsupported struct {
	Selector string
	Reason   string
}

// Result is the outcome of evaluating a request.
type Result struct {
	Allowed     bool
	Matches     []Match
	Unsupported []Unsupported
}

// Evaluate checks every grant in the tailnet against the request.
func Evaluate(t *tailnet.Tailnet, req Request) Result {
	srcSels := SourceSelectors(t, req)
	var res Result

	for _, g := range t.Grants {
		matched := false
		var chain []string

		for _, src := range g.Sources {
			if !contains(srcSels, src) {
				continue
			}
			for _, dst := range g.Destinations {
				host, port, ok := splitDst(dst)
				if !ok {
					res.Unsupported = append(res.Unsupported, Unsupported{dst, "unrecognized destination format"})
					continue
				}
				dstMatch, how := matchDestination(t, host, req)
				if !dstMatch {
					continue
				}
				portOK, why := matchPorts(g.IP, port, req.Port, req.Proto)
				if !portOK {
					continue
				}
				if len(g.SrcPosture) > 0 {
					res.Unsupported = append(res.Unsupported, Unsupported{
						fmt.Sprintf("srcPosture %s", strings.Join(g.SrcPosture, ",")),
						"posture evaluation is not yet supported; access may be more restrictive than shown",
					})
				}
				if !matched {
					chain = append(chain,
						fmt.Sprintf("source %q matches via %s", describeSource(req), src),
						fmt.Sprintf("destination matches %s (%s)", dst, how),
						fmt.Sprintf("ports allow %s", why),
					)
					matched = true
				}
			}
			if matched {
				break
			}
		}
		if matched {
			res.Matches = append(res.Matches, Match{Grant: g, Chain: chain})
		}
	}

	res.Allowed = len(res.Matches) > 0
	return res
}

// SourceSelectors returns every selector that represents the request's source:
// login name, group memberships, role autogroups, and device tags.
func SourceSelectors(t *tailnet.Tailnet, req Request) []string {
	var sels []string
	if req.SourceLogin != "" {
		sels = append(sels, req.SourceLogin, "*")
		sels = append(sels, t.GroupsOfUser(req.SourceLogin)...)
		sels = append(sels, "autogroup:member")
		if u := t.FindUser(req.SourceLogin); u != nil && tailnet.CanManage(u.Role) {
			sels = append(sels, "autogroup:admin")
		}
	}
	sels = append(sels, req.SourceTags...)
	return sels
}

func matchDestination(t *tailnet.Tailnet, host string, req Request) (bool, string) {
	switch {
	case host == "*":
		return true, "wildcard"
	case strings.HasPrefix(host, "tag:"):
		for _, dt := range req.DestTags {
			if dt == host {
				return true, fmt.Sprintf("device carries %s", host)
			}
		}
		return false, ""
	case strings.HasPrefix(host, "autogroup:self"):
		return req.DestOwner != "" && req.DestOwner == req.SourceLogin, "destination owned by source user"
	case strings.HasPrefix(host, "autogroup:"):
		// autogroup:internet etc. cannot be reliably matched to a device here
		return false, ""
	case strings.HasPrefix(host, "group:") || strings.Contains(host, "@"):
		// users/groups are not valid packet destinations; ignore for device matching
		return false, ""
	default:
		// IP, CIDR, or host alias
		targets := append([]string(nil), req.DestIPs...)
		if ip, ok := t.Hosts[host]; ok {
			targets = append(targets, ip)
		} else if !looksLikeIPOrCIDR(host) {
			// hostname-style destination: compare against device DNS names elsewhere;
			// for packet-level matching we only know IPs
			return false, ""
		}
		for _, dip := range targets {
			if ipMatches(host, dip) {
				return true, fmt.Sprintf("%s covers %s", host, dip)
			}
		}
		return false, ""
	}
}

// matchPorts reports whether the grant's ip entries permit the requested
// destination port. grantPort is the port embedded in the dst selector.
func matchPorts(grantIPs []string, grantDstPort, wantPort, proto string) (bool, string) {
	if len(grantIPs) == 0 && grantDstPort == "*" {
		return true, "(grant has no ip restriction)"
	}
	effective := grantIPs
	if len(effective) == 0 {
		// legacy ACL ports were normalized into IP entries at collect time
		effective = []string{"*"}
	}
	for _, entry := range effective {
		pProto, pSpec, hasProto := strings.Cut(entry, ":")
		if !hasProto {
			pProto, pSpec = "", entry
		}
		if hasProto && proto != "" && !strings.EqualFold(pProto, proto) {
			continue
		}
		if pSpec == "*" || pSpec == "" {
			return true, entry
		}
		want := coalesce(wantPort, grantDstPort)
		if want == "*" || want == "" {
			continue // need a concrete port to confirm; wildcard dst port means any
		}
		if portInRange(pSpec, want) {
			return true, fmt.Sprintf("%s (requested %s)", entry, want)
		}
	}
	return false, ""
}

func portInRange(spec, port string) bool {
	if spec == port {
		return true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		p := atoi(port)
		return p >= atoi(lo) && p <= atoi(hi)
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// splitDst splits "tag:prod:5432" into ("tag:prod", "5432", true).
// The tag/user prefix contains a colon itself, so only the last colon splits.
func splitDst(dst string) (host, port string, ok bool) {
	i := strings.LastIndex(dst, ":")
	if i < 0 {
		return dst, "*", true
	}
	host, port = dst[:i], dst[i+1:]
	// make sure the part after the last colon is actually a port or *
	if port != "*" && atoi(port) < 0 {
		return dst, "*", true
	}
	return host, port, true
}

func ipMatches(selector, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return selector == ip
	}
	if prefix, err := netip.ParsePrefix(selector); err == nil {
		return prefix.Contains(addr)
	}
	selAddr, err := netip.ParseAddr(selector)
	if err != nil {
		return selector == ip
	}
	return selAddr == addr
}

func looksLikeIPOrCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func describeSource(req Request) string {
	if req.SourceLogin != "" {
		return req.SourceLogin
	}
	return strings.Join(req.SourceTags, ", ")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Package audit runs checks over a collected tailnet snapshot and produces
// explainable findings. Checks are pure functions of the snapshot.
package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
	Info   Severity = "INFO"
)

var severityOrder = map[Severity]int{High: 0, Medium: 1, Low: 2, Info: 3}

// Finding is a single explainable audit result.
type Finding struct {
	Severity Severity
	Title    string
	Detail   string
	Evidence []string
	Why      string
	Next     string
}

type checkFunc func(*tailnet.Tailnet) []Finding

var checks = []checkFunc{
	checkStaleDevices,
	checkKeyExpiry,
	checkOutdatedClients,
	checkBroadGrants,
	checkUnapprovedRoutes,
	checkSingleExitNode,
	checkOrphanedTags,
	checkInactiveUsers,
	checkPrivilegedUserDevices,
}

// Run executes all checks and returns findings sorted by severity.
func Run(t *tailnet.Tailnet) []Finding {
	var findings []Finding
	for _, check := range checks {
		findings = append(findings, check(t)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})
	return findings
}

func checkStaleDevices(t *tailnet.Tailnet) []Finding {
	var stale30, stale90 []*tailnet.Device
	for _, d := range t.Devices {
		if d.Online || d.LastSeen.IsZero() || d.IsEphemeral {
			continue
		}
		idle := time.Since(d.LastSeen)
		if idle > 90*24*time.Hour {
			stale90 = append(stale90, d)
		} else if idle > 30*24*time.Hour {
			stale30 = append(stale30, d)
		}
	}
	var out []Finding
	if len(stale90) > 0 {
		out = append(out, Finding{
			Severity: Medium,
			Title:    fmt.Sprintf("%d device(s) unseen for over 90 days", len(stale90)),
			Detail:   "These devices have not connected to the tailnet in more than 90 days but still exist.",
			Evidence: evidenceDevices(stale90),
			Why:      "Stale devices may hold expired-but-recoverable keys, still reference tags or grants, and inflate the blast radius of your policy.",
			Next:     "Confirm the devices are decommissioned, then remove them from the admin console.",
		})
	}
	if len(stale30) > 0 {
		out = append(out, Finding{
			Severity: Low,
			Title:    fmt.Sprintf("%d device(s) unseen for over 30 days", len(stale30)),
			Detail:   "These devices have not connected recently but were seen within the last 90 days.",
			Evidence: evidenceDevices(stale30),
			Why:      "Long-absent devices may be lost, reimaged, or belong to people who left.",
			Next:     "Check with device owners whether these are still in use.",
		})
	}
	return out
}

func checkKeyExpiry(t *tailnet.Tailnet) []Finding {
	var out []Finding
	var expired, expiring, noExpiry []*tailnet.Device
	for _, d := range t.Devices {
		if d.KeyExpiryDisabled {
			noExpiry = append(noExpiry, d)
			continue
		}
		if d.Expires.IsZero() {
			continue
		}
		until := time.Until(d.Expires)
		switch {
		case until <= 0:
			expired = append(expired, d)
		case until < 14*24*time.Hour:
			expiring = append(expiring, d)
		}
	}
	if len(expired) > 0 {
		out = append(out, Finding{
			Severity: Medium,
			Title:    fmt.Sprintf("%d device(s) with expired node keys", len(expired)),
			Detail:   "These devices cannot reconnect until their keys are renewed.",
			Evidence: evidenceDevices(expired),
			Why:      "Expired devices are often forgotten; if they are intentionally kept, they should be removed instead.",
			Next:     "Renew or delete these devices.",
		})
	}
	if len(expiring) > 0 {
		out = append(out, Finding{
			Severity: Low,
			Title:    fmt.Sprintf("%d device(s) with keys expiring within 14 days", len(expiring)),
			Detail:   "These devices will lose connectivity when their keys expire unless renewed.",
			Evidence: evidenceDevices(expiring),
			Why:      "Unexpected key expiry causes outages that look like network failures.",
			Next:     "Have owners re-authenticate, or extend expiry via the admin console.",
		})
	}
	if len(noExpiry) > 0 {
		out = append(out, Finding{
			Severity: Low,
			Title:    fmt.Sprintf("%d device(s) with key expiry disabled", len(noExpiry)),
			Detail:   "Key expiry is disabled on these devices, so their node keys never expire.",
			Evidence: evidenceDevices(noExpiry),
			Why:      "Devices that never re-authenticate accumulate stale access over time and will survive owner departure.",
			Next:     "Verify each is intentionally permanent (e.g. servers); consider re-enabling expiry elsewhere.",
		})
	}
	return out
}

func checkOutdatedClients(t *tailnet.Tailnet) []Finding {
	var outdated []*tailnet.Device
	for _, d := range t.Devices {
		if d.UpdateAvailable {
			outdated = append(outdated, d)
		}
	}
	if len(outdated) == 0 {
		return nil
	}
	return []Finding{{
		Severity: Info,
		Title:    fmt.Sprintf("%d device(s) have a Tailscale update available", len(outdated)),
		Detail:   "These devices report an available client update.",
		Evidence: evidenceDevices(outdated),
		Why:      "Older clients may lack recent fixes and can behave differently during debugging.",
		Next:     "Update clients when convenient; prioritize devices that provide routes or services.",
	}}
}

func checkBroadGrants(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, g := range t.Grants {
		allPorts := len(g.App) == 0 && hasAllPorts(g.IP)
		wildcardDst := hasWildcardDestination(g.Destinations)
		wildcardSrc := contains(g.Sources, "*") || contains(g.Sources, "autogroup:member")

		switch {
		case wildcardSrc && wildcardDst && allPorts:
			out = append(out, Finding{
				Severity: High,
				Title:    "Grant allows everything to everyone",
				Detail:   "A grant matches every source, every destination, on all ports.",
				Evidence: grantEvidence(g),
				Why:      "This neutralizes tailnet access control entirely; any compromised device can reach any other.",
				Next:     "Replace with explicit grants per source and destination. If this is intentional for a lab tailnet, document it.",
			})
		case wildcardDst && len(g.IP) == 0 && len(g.App) == 0:
			out = append(out, Finding{
				Severity: High,
				Title:    "Grant allows all destinations",
				Detail:   "A grant grants access to every device in the tailnet.",
				Evidence: grantEvidence(g),
				Why:      "Any compromise of a covered source exposes the entire tailnet.",
				Next:     "Restrict destinations to specific tags, hosts, or subnets.",
			})
		case allPorts && len(g.Destinations) > 0:
			out = append(out, Finding{
				Severity: Medium,
				Title:    "Grant allows all ports",
				Detail:   "A grant permits every port to its destinations rather than required ports only.",
				Evidence: grantEvidence(g),
				Why:      "All-port access exposes management interfaces and databases that were only meant to be reachable incidentally.",
				Next:     "List the ports actually used by the destination services.",
			})
		}
	}
	return out
}

func checkUnapprovedRoutes(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, d := range t.Devices {
		enabled := map[string]bool{}
		for _, r := range d.EnabledRoutes {
			enabled[r] = true
		}
		var unapproved []string
		for _, r := range d.AdvertisedRoutes {
			if !enabled[r] {
				unapproved = append(unapproved, r)
			}
		}
		if len(unapproved) == 0 {
			continue
		}
		out = append(out, Finding{
			Severity: Medium,
			Title:    fmt.Sprintf("%s advertises route(s) that are not enabled", d.Hostname),
			Detail:   "The device advertises subnet routes that have not been approved, so traffic to those subnets will not route through it.",
			Evidence: append([]string{
				fmt.Sprintf("device: %s (%s)", d.Hostname, orDash(d.Owner)),
				fmt.Sprintf("advertised but not enabled: %s", strings.Join(unapproved, ", ")),
			}, autoApproverEvidence(t)...),
			Why:  "This usually means someone expected subnet routing to work and it silently does not.",
			Next: "Approve the routes in the admin console, or add an autoApprovers rule if they should self-approve.",
		})
	}
	return out
}

func checkSingleExitNode(t *tailnet.Tailnet) []Finding {
	var exitNodes []*tailnet.Device
	for _, d := range t.Devices {
		if !d.Authorized || !d.Online {
			continue
		}
		for _, r := range d.EnabledRoutes {
			if r == "0.0.0.0/0" || r == "::/0" {
				exitNodes = append(exitNodes, d)
				break
			}
		}
	}
	if len(exitNodes) != 1 {
		return nil
	}
	d := exitNodes[0]
	return []Finding{{
		Severity: Low,
		Title:    "Only one exit node exists",
		Detail:   fmt.Sprintf("%s is the only advertised exit node in the tailnet.", d.Hostname),
		Evidence: []string{
			fmt.Sprintf("device: %s (%s)", d.Hostname, orDash(d.Owner)),
			fmt.Sprintf("online: %v", d.Online),
		},
		Why:  "If this device goes down, every exit-node user loses external connectivity at once.",
		Next: "Consider a second exit node, or confirm the single point of failure is acceptable.",
	}}
}

func checkOrphanedTags(t *tailnet.Tailnet) []Finding {
	var out []Finding

	used := map[string]bool{}
	for _, d := range t.Devices {
		for _, tag := range d.Tags {
			used[tag] = true
			if _, owned := t.TagOwners[tag]; !owned {
				out = append(out, Finding{
					Severity: Medium,
					Title:    fmt.Sprintf("Device carries tag %s with no tagOwners entry", tag),
					Detail:   "The tag is applied to devices but nothing in the policy file defines who owns it.",
					Evidence: []string{fmt.Sprintf("devices: %s", strings.Join(deviceNames(t.DevicesWithTag(tag)), ", "))},
					Why:      "Without owners, nobody can manage or re-assign this tag through normal policy, and grants referencing it are hard to reason about.",
					Next:     fmt.Sprintf("Add %s to tagOwners in the policy file.", tag),
				})
			}
		}
	}

	var unused []string
	for tag := range t.TagOwners {
		if !used[tag] {
			unused = append(unused, tag)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		out = append(out, Finding{
			Severity: Info,
			Title:    fmt.Sprintf("%d tag(s) defined in tagOwners but unused", len(unused)),
			Detail:   "No device currently carries these tags.",
			Evidence: []string{"unused tags: " + strings.Join(unused, ", ")},
			Why:      "Unused tags may be leftovers from decommissioned infrastructure or preparation for future use.",
			Next:     "Remove stale tags or keep if intentionally reserved.",
		})
	}
	return out
}

func checkInactiveUsers(t *tailnet.Tailnet) []Finding {
	var out []Finding
	var suspended, idle []*tailnet.User
	for _, u := range t.Users {
		switch u.Status {
		case "suspended":
			suspended = append(suspended, u)
		case "idle":
			if time.Since(u.LastSeen) > 90*24*time.Hour {
				idle = append(idle, u)
			}
		}
	}
	if len(suspended) > 0 {
		names := userNames(suspended)
		references := referencedInPolicy(t, names)
		if len(references) > 0 {
			out = append(out, Finding{
				Severity: Low,
				Title:    fmt.Sprintf("%d suspended user(s) still referenced in the tailnet", len(suspended)),
				Detail:   "Suspended users cannot authenticate, but their group memberships and grants remain in the policy file.",
				Evidence: append([]string{"suspended: " + strings.Join(names, ", ")}, references...),
				Why:      "If the account is later restored, any policy references reactivate with it.",
				Next:     "Remove suspended users from groups and grants, or delete the accounts.",
			})
		}
	}
	if len(idle) > 0 {
		out = append(out, Finding{
			Severity: Info,
			Title:    fmt.Sprintf("%d user(s) inactive for over 90 days", len(idle)),
			Detail:   "These users have not connected recently.",
			Evidence: []string{"inactive: " + strings.Join(userNames(idle), ", ")},
			Why:      "Inactive accounts holding group memberships widen the effective blast radius of those groups.",
			Next:     "Confirm the accounts are still needed.",
		})
	}
	return out
}

func checkPrivilegedUserDevices(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, d := range t.Devices {
		if d.Owner == "" || len(d.AdvertisedRoutes) == 0 {
			continue
		}
		out = append(out, Finding{
			Severity: Low,
			Title:    fmt.Sprintf("User-owned device %s provides routing", d.Hostname),
			Detail:   "A personally-owned device (not tagged) acts as a subnet router or exit node.",
			Evidence: []string{
				fmt.Sprintf("device: %s, owner: %s", d.Hostname, d.Owner),
				fmt.Sprintf("advertises: %s", strings.Join(d.AdvertisedRoutes, ", ")),
			},
			Why:  "Routing depends on an individual's laptop/server staying online and updated; tagged infrastructure devices are easier to govern.",
			Next: "Consider moving routing duties to a tagged infrastructure device owned by the tailnet.",
		})
	}
	return out
}

// --- helpers ---

func evidenceDevices(devs []*tailnet.Device) []string {
	var ev []string
	for _, d := range devs {
		line := fmt.Sprintf("%s (%s, %s)", d.Hostname, orDash(d.OS), orDash(d.Owner))
		if !d.LastSeen.IsZero() {
			line += fmt.Sprintf(", last seen %s", d.LastSeen.Format("2006-01-02"))
		}
		ev = append(ev, line)
	}
	return ev
}

func grantEvidence(g *tailnet.Grant) []string {
	kind := "grant"
	if g.Legacy {
		kind = "legacy acl"
	}
	return []string{
		fmt.Sprintf("[%s] src: %s", kind, strings.Join(g.Sources, ", ")),
		fmt.Sprintf("dst: %s", strings.Join(g.Destinations, ", ")),
		fmt.Sprintf("ip: %s", orDefault(strings.Join(g.IP, ", "), "(all)")),
	}
}

func autoApproverEvidence(t *tailnet.Tailnet) []string {
	var ev []string
	for route, approvers := range t.AutoApprovers.Routes {
		ev = append(ev, fmt.Sprintf("autoApprovers: %s approved by %s", route, strings.Join(approvers, ", ")))
	}
	return ev
}

func deviceNames(devs []*tailnet.Device) []string {
	var names []string
	for _, d := range devs {
		names = append(names, d.Hostname)
	}
	return names
}

func userNames(users []*tailnet.User) []string {
	var names []string
	for _, u := range users {
		names = append(names, u.LoginName)
	}
	return names
}

func referencedInPolicy(t *tailnet.Tailnet, logins []string) []string {
	var refs []string
	for g, members := range t.Groups {
		for _, m := range members {
			if contains(logins, m) {
				refs = append(refs, "group: "+g)
			}
		}
	}
	for _, grant := range t.Grants {
		for _, source := range grant.Sources {
			if contains(logins, source) {
				refs = append(refs, "grant source: "+source)
			}
		}
	}
	for tag, owners := range t.TagOwners {
		for _, owner := range owners {
			if contains(logins, owner) {
				refs = append(refs, "tag owner: "+tag)
			}
		}
	}
	for route, approvers := range t.AutoApprovers.Routes {
		for _, approver := range approvers {
			if contains(logins, approver) {
				refs = append(refs, "route auto approver: "+route)
			}
		}
	}
	for _, approver := range t.AutoApprovers.ExitNode {
		if contains(logins, approver) {
			refs = append(refs, "exit-node auto approver: "+approver)
		}
	}
	for service, approvers := range t.AutoApprovers.Services {
		for _, approver := range approvers {
			if contains(logins, approver) {
				refs = append(refs, "service auto approver: "+service)
			}
		}
	}
	sort.Strings(refs)
	return refs
}

func hasAllPorts(entries []string) bool {
	for _, entry := range entries {
		if entry == "*" || entry == "*:*" || strings.HasSuffix(entry, ":*") {
			return true
		}
	}
	return false
}

func hasWildcardDestination(destinations []string) bool {
	for _, dst := range destinations {
		if dst == "*" || strings.HasPrefix(dst, "*:") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Package audit runs checks over a collected tailnet snapshot and produces
// explainable findings. Checks are pure functions of the snapshot.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/policy"
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
	RuleID   string `json:",omitempty"`
	Subject  string `json:",omitempty"`
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
	checkSSHAccess,
	checkFunnelExposure,
	checkAuthKeys,
	checkTailnetSettings,
	checkCollectionGaps,
}

// CheckNames lists stable filter names in the same order as checks,
// for --only/--exclude and --list-checks.
var CheckNames = []string{
	"stale-devices",
	"key-expiry",
	"outdated-clients",
	"broad-grants",
	"unapproved-routes",
	"single-exit-node",
	"orphaned-tags",
	"inactive-users",
	"privileged-user-devices",
	"ssh-access",
	"funnel-exposure",
	"auth-keys",
	"tailnet-settings",
	"collection-gaps",
}

// checkSummaries describes each check for SARIF rule metadata, independently
// of the per-finding titles that embed counts and names.
var checkSummaries = map[string]string{
	"stale-devices":           "Devices that have not connected recently",
	"key-expiry":              "Expired, expiring, or non-expiring node keys",
	"outdated-clients":        "Devices with a Tailscale update available",
	"broad-grants":            "Access rules with wildcard destinations or all ports",
	"unapproved-routes":       "Advertised routes that are not enabled",
	"single-exit-node":        "A single exit node with no redundancy",
	"orphaned-tags":           "Tags without owners, or owners without tagged devices",
	"inactive-users":          "Suspended or inactive users still in policy",
	"privileged-user-devices": "User-owned devices providing routing",
	"ssh-access":              "Tailscale SSH rules allowing root or wide access without re-authentication",
	"funnel-exposure":         "Funnel enabled for devices, exposing them to the internet",
	"auth-keys":               "Long-lived reusable auth keys",
	"tailnet-settings":        "Tailnet settings that weaken device or user admission",
	"collection-gaps":         "Optional audit data the credentials could not read",
}

// Run executes all checks and returns findings sorted by severity.
func Run(t *tailnet.Tailnet) []Finding {
	return RunFiltered(t, nil, nil)
}

// RunFiltered runs a subset of checks. If only is non-empty, only those named
// checks run; exclude removes checks by name. Unknown names are ignored.
func RunFiltered(t *tailnet.Tailnet, only, exclude []string) []Finding {
	onlySet := map[string]bool{}
	for _, n := range only {
		onlySet[n] = true
	}
	exclSet := map[string]bool{}
	for _, n := range exclude {
		exclSet[n] = true
	}
	var findings []Finding
	for i, check := range checks {
		name := ""
		if i < len(CheckNames) {
			name = CheckNames[i]
		}
		if len(onlySet) > 0 && !onlySet[name] {
			continue
		}
		if exclSet[name] {
			continue
		}
		for _, f := range check(t) {
			f.RuleID = name
			if f.Subject == "" {
				f.Subject = findingSubject(name, f)
			}
			findings = append(findings, f)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})
	return findings
}

// referenceTime returns CollectedAt when set (deterministic for snapshots)
// and falls back to wall-clock otherwise.
func referenceTime(t *tailnet.Tailnet) time.Time {
	if t != nil && !t.CollectedAt.IsZero() {
		return t.CollectedAt
	}
	return time.Now()
}

func checkStaleDevices(t *tailnet.Tailnet) []Finding {
	var stale30, stale90 []*tailnet.Device
	now := referenceTime(t)
	for _, d := range t.Devices {
		if d == nil || d.Online || d.LastSeen.IsZero() || d.IsEphemeral {
			continue
		}
		idle := now.Sub(d.LastSeen)
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
	now := referenceTime(t)
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
		if d.KeyExpiryDisabled {
			noExpiry = append(noExpiry, d)
			continue
		}
		if d.Expires.IsZero() {
			continue
		}
		until := d.Expires.Sub(now)
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
		if d == nil {
			continue
		}
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
		if g == nil || (!g.Legacy && len(g.IP) == 0) {
			continue // no packet access, whatever its selectors say
		}
		scope := grantScope(g)
		switch {
		case hasWildcard(g.Sources) && scope.wildcardAllPorts:
			out = append(out, Finding{
				Severity: High,
				Title:    "Grant allows everything to everyone",
				Detail:   "A grant matches every source, every destination, on all ports.",
				Evidence: grantEvidence(g),
				Why:      "This neutralizes tailnet access control entirely; any compromised device can reach any other.",
				Next:     "Replace with explicit grants per source and destination. If this is intentional for a lab tailnet, document it.",
			})
		case scope.wildcardDst:
			out = append(out, Finding{
				Severity: High,
				Title:    "Grant allows all destinations",
				Detail:   "A grant grants access to every device in the tailnet.",
				Evidence: grantEvidence(g),
				Why:      "Any compromise of a covered source exposes the entire tailnet.",
				Next:     "Restrict destinations to specific tags, hosts, or subnets.",
			})
		case scope.allPorts:
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

type destinationScope struct {
	wildcardDst, allPorts, wildcardAllPorts bool
}

// grantScope gives legacy ACLs and modern grants the same answer. They differ
// only in where ports live: in the destination or in the ip field.
func grantScope(g *tailnet.Grant) destinationScope {
	var scope destinationScope
	for _, dst := range g.Destinations {
		host, ports := dst, ""
		if h, p, ok := policy.SplitDestination(dst); ok {
			host, ports = h, p
		}
		all := hasAllPorts(g.IP)
		if g.Legacy {
			all = coversAllPorts(ports) && (len(g.IP) == 0 || hasAllPorts(g.IP))
		}
		wildcard := isWildcard(host)
		scope.wildcardDst = scope.wildcardDst || wildcard
		scope.allPorts = scope.allPorts || all
		scope.wildcardAllPorts = scope.wildcardAllPorts || (wildcard && all)
	}
	return scope
}

func checkUnapprovedRoutes(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
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
			Subject:  deviceSubject(d),
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
		if d == nil {
			continue
		}
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
	orphans := map[string]bool{}
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
		for _, tag := range d.Tags {
			used[tag] = true
			if _, owned := t.TagOwners[tag]; !owned {
				orphans[tag] = true
			}
		}
	}
	// One finding per orphan tag (not per device): O(T) with a single
	// DevicesWithTag lookup per tag instead of per device occurrence.
	sortedOrphans := make([]string, 0, len(orphans))
	for tag := range orphans {
		sortedOrphans = append(sortedOrphans, tag)
	}
	sort.Strings(sortedOrphans)
	for _, tag := range sortedOrphans {
		out = append(out, Finding{
			Severity: Medium,
			Title:    fmt.Sprintf("Tag %s has no tagOwners entry", tag),
			Detail:   "The tag is applied to devices but nothing in the policy file defines who owns it.",
			Evidence: []string{fmt.Sprintf("devices: %s", strings.Join(deviceNames(t.DevicesWithTag(tag)), ", "))},
			Why:      "Without owners, nobody can manage or re-assign this tag through normal policy, and grants referencing it are hard to reason about.",
			Next:     fmt.Sprintf("Add %s to tagOwners in the policy file.", tag),
		})
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
	now := referenceTime(t)
	for _, u := range t.Users {
		if u == nil {
			continue
		}
		switch u.Status {
		case "suspended":
			suspended = append(suspended, u)
		case "idle":
			if u.LastSeen.IsZero() {
				continue
			}
			if now.Sub(u.LastSeen) > 90*24*time.Hour {
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
		if d == nil {
			continue
		}
		if d.Owner == "" || len(d.Tags) > 0 || len(d.AdvertisedRoutes) == 0 {
			continue
		}
		out = append(out, Finding{
			Severity: Low,
			Title:    fmt.Sprintf("User-owned device %s provides routing", d.Hostname),
			Subject:  deviceSubject(d),
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

func checkSSHAccess(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, r := range t.SSHRules {
		// A check rule makes the user re-authenticate, so only accept is standing access.
		if r == nil || !strings.EqualFold(r.Action, "accept") {
			continue
		}
		root := contains(r.Users, "root") || contains(r.Users, "*")
		wide := hasWildcard(r.Sources)
		if !root && !wide {
			continue
		}
		evidence := []string{
			"src: " + sortedJoin(r.Sources),
			"dst: " + sortedJoin(r.Destinations),
			"users: " + sortedJoin(r.Users),
		}
		switch {
		case root && wide:
			out = append(out, Finding{
				Severity: High,
				Title:    "SSH rule gives broad root access without re-authentication",
				Detail:   "An accept rule lets a wildcard source log in as root.",
				Evidence: evidence,
				Why:      "A single compromised device or account becomes root on every destination the rule covers.",
				Next:     "Narrow the sources, use autogroup:nonroot, or change the action to check.",
			})
		case root:
			out = append(out, Finding{
				Severity: Medium,
				Title:    "SSH rule allows root without re-authentication",
				Detail:   "An accept rule permits root logins with no periodic check.",
				Evidence: evidence,
				Why:      "Standing root access outlives the moment it was needed and survives a stolen session.",
				Next:     "Change the action to check, or log in as a non-root user.",
			})
		default:
			out = append(out, Finding{
				Severity: Low,
				Title:    "SSH rule allows every user without re-authentication",
				Detail:   "An accept rule lets a wildcard source log in as non-root users.",
				Evidence: evidence,
				Why:      "Any member's compromised device gets a shell on the destinations.",
				Next:     "Restrict sources to the groups that need SSH.",
			})
		}
	}
	return out
}

func checkFunnelExposure(t *tailnet.Tailnet) []Finding {
	var out []Finding
	for _, a := range t.NodeAttrs {
		if a == nil || !contains(a.Attrs, "funnel") {
			continue
		}
		f := Finding{
			Severity: Low,
			Title:    "Funnel is enabled",
			Detail:   "A nodeAttrs rule lets the targeted devices publish services to the public internet.",
			Evidence: []string{"target: " + sortedJoin(a.Targets)},
			Why:      "Funnel traffic comes from outside the tailnet, so access rules do not protect the published service.",
			Next:     "Confirm each target should be internet-reachable.",
		}
		if hasWildcard(a.Targets) {
			f.Severity = Medium
			f.Title = "Funnel is enabled for every device"
			f.Next = "Limit the funnel attribute to the tags that need it."
		}
		out = append(out, f)
	}
	return out
}

// Auth keys last at most 90 days, so this leaves the ones with most of that ahead.
const longLivedKey = 30 * 24 * time.Hour

func checkAuthKeys(t *tailnet.Tailnet) []Finding {
	var out []Finding
	now := referenceTime(t)
	for _, k := range t.AuthKeys {
		if k == nil || !k.Reusable || k.Expires.IsZero() {
			continue
		}
		left := k.Expires.Sub(now)
		if left <= longLivedKey {
			continue
		}
		f := Finding{
			Severity: Low,
			Title:    "Reusable auth key has more than 30 days left",
			Subject:  k.ID,
			Detail:   "A reusable auth key can join any number of devices until it expires.",
			Evidence: []string{
				fmt.Sprintf("key: %s (%s)", k.ID, orDash(k.Description)),
				"expires: " + k.Expires.Format("2006-01-02"),
				fmt.Sprintf("tags: %s, ephemeral: %t, preauthorized: %t", orDash(sortedJoin(k.Tags)), k.Ephemeral, k.Preauthorized),
			},
			Why:  "A leaked reusable key is a standing way into the tailnet.",
			Next: "Prefer short-lived or single-use keys, or an OAuth client that mints them.",
		}
		if k.Preauthorized {
			f.Severity = Medium
			f.Title = "Reusable pre-authorized auth key has more than 30 days left"
			f.Why = "A leaked pre-authorized key joins devices without passing device approval."
		}
		out = append(out, f)
	}
	return out
}

func checkTailnetSettings(t *tailnet.Tailnet) []Finding {
	s := t.Settings
	if s == nil {
		return nil
	}
	var out []Finding
	if !s.DevicesApprovalOn {
		out = append(out, Finding{
			Severity: Low,
			Title:    "Device approval is off",
			Detail:   "New devices join the tailnet without an admin approving them.",
			Why:      "Any stolen login or auth key can add a device immediately.",
			Next:     "Turn on device approval in the admin console's device settings.",
		})
	}
	if !s.UsersApprovalOn {
		out = append(out, Finding{
			Severity: Low,
			Title:    "User approval is off",
			Detail:   "Anyone who can sign in to your identity provider domain can join the tailnet.",
			Why:      "Access follows the identity provider alone, with no tailnet-side review.",
			Next:     "Turn on user approval in the admin console's user settings.",
		})
	}
	if s.DevicesKeyDurationDays > 180 {
		out = append(out, Finding{
			Severity: Low,
			Title:    "Device key lifetime is over 180 days",
			Detail:   fmt.Sprintf("Device keys last %d days before re-authentication.", s.DevicesKeyDurationDays),
			Why:      "A long key lifetime lets a lost device stay connected for months.",
			Next:     "Shorten the key expiry in the admin console's device settings.",
		})
	}
	if !s.DevicesAutoUpdatesOn {
		out = append(out, Finding{
			Severity: Info,
			Title:    "Client auto-updates are off by default",
			Detail:   "New devices do not enable Tailscale auto-updates by default.",
			Why:      "Security fixes reach devices only when someone updates them.",
			Next:     "Turn on auto-updates in the admin console's device settings.",
		})
	}
	return out
}

func checkCollectionGaps(t *tailnet.Tailnet) []Finding {
	if len(t.CollectionGaps) == 0 {
		return nil
	}
	return []Finding{{
		Severity: Info,
		Title:    "Some optional audit data could not be read",
		Detail:   "Checks that depend on this data were skipped.",
		Evidence: t.CollectionGaps,
		Why:      "A clean result for those checks only means they did not run.",
		Next:     "Grant the credentials read access to this data.",
	}}
}

// --- helpers ---

func evidenceDevices(devs []*tailnet.Device) []string {
	var ev []string
	for _, d := range devs {
		if d == nil {
			continue
		}
		line := fmt.Sprintf("%s (%s, %s)", d.Hostname, orDash(d.OS), orDash(d.Owner))
		if !d.LastSeen.IsZero() {
			line += fmt.Sprintf(", last seen %s", d.LastSeen.Format("2006-01-02"))
		}
		ev = append(ev, line)
	}
	return ev
}

func grantEvidence(g *tailnet.Grant) []string {
	if g == nil {
		return []string{"[grant] (nil)"}
	}
	kind := "grant"
	if g.Legacy {
		kind = "legacy acl"
	}
	return []string{
		fmt.Sprintf("[%s] src: %s", kind, sortedJoin(g.Sources)),
		fmt.Sprintf("dst: %s", sortedJoin(g.Destinations)),
		fmt.Sprintf("ip: %s", g.NetworkSummary()),
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
		if d == nil {
			continue
		}
		names = append(names, d.Hostname)
	}
	return names
}

func userNames(users []*tailnet.User) []string {
	var names []string
	for _, u := range users {
		if u == nil {
			continue
		}
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
		if grant == nil {
			continue
		}
		for _, source := range grant.Sources {
			if contains(logins, source) {
				refs = append(refs, "grant source: "+source)
			}
		}
		for _, destination := range grant.Destinations {
			if host, _, ok := policy.SplitDestination(destination); ok && contains(logins, host) {
				refs = append(refs, "grant destination: "+host)
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
	return slices.Compact(refs)
}

func hasAllPorts(entries []string) bool {
	for _, entry := range entries {
		_, spec, qualified := strings.Cut(entry, ":")
		if !qualified {
			spec = entry
		}
		if coversAllPorts(spec) {
			return true
		}
	}
	return false
}

// coversAllPorts also accepts spelled-out ranges. Port 0 is not a real service
// port, so 1-65535 counts.
func coversAllPorts(spec string) bool {
	for _, r := range policy.PortRanges(spec) {
		if r[0] <= 1 && r[1] == 65535 {
			return true
		}
	}
	return false
}

func isWildcard(selector string) bool {
	switch selector {
	case "*", "autogroup:danger-all", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

func hasWildcard(selectors []string) bool {
	for _, s := range selectors {
		if isWildcard(s) || s == "autogroup:member" {
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

// Subjects identify the issue rather than mutable evidence such as last-seen
// dates and affected-device counts. Aggregate findings track a check category.
var leadingCount = regexp.MustCompile(`^\d+\s+`)

func findingSubject(rule string, f Finding) string {
	title := leadingCount.ReplaceAllString(f.Title, "")
	switch rule {
	case "broad-grants", "ssh-access", "funnel-exposure":
		ev := append([]string(nil), f.Evidence...)
		sort.Strings(ev)
		sum := sha256.Sum256([]byte(strings.Join(ev, "\x00")))
		return hex.EncodeToString(sum[:])
	}
	return title
}

func sortedJoin(values []string) string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	return strings.Join(copy, ", ")
}

func deviceSubject(d *tailnet.Device) string {
	if d.ID != "" {
		return d.ID
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	return d.Name
}

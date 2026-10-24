package policy

import (
	"strings"

	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Normalize replaces all policy fields, retaining the inventory and collection
// time. It allocates fresh maps so applying a policy to a shallow snapshot copy
// cannot alter the baseline's policy maps.
func Normalize(t *tailnet.Tailnet, acl *tailscale.ACL) {
	t.Groups = make(map[string][]string, len(acl.Groups))
	t.TagOwners = make(map[string][]string, len(acl.TagOwners))
	t.Hosts = make(map[string]string, len(acl.Hosts))
	t.IPSets = make(map[string][]string, len(acl.IPSets))
	t.Postures = make(map[string][]string, len(acl.Postures))
	t.Grants = nil
	t.AutoApprovers = tailnet.AutoApprovers{}
	for name, ranges := range acl.IPSets {
		t.IPSets[name] = ranges
	}
	for name, members := range acl.Groups {
		t.Groups[name] = members
	}
	for tag, owners := range acl.TagOwners {
		if !strings.Contains(tag, ":") {
			tag = "tag:" + tag
		}
		t.TagOwners[tag] = owners
	}
	for name, ip := range acl.Hosts {
		t.Hosts[name] = ip
	}
	for name, conditions := range acl.Postures {
		t.Postures[name] = conditions
	}
	if acl.AutoApprovers != nil {
		t.AutoApprovers = tailnet.AutoApprovers{
			Routes: acl.AutoApprovers.Routes, ExitNode: acl.AutoApprovers.ExitNode,
			Services: acl.AutoApprovers.Services,
		}
	}
	t.HasAccessRules = acl.ACLs != nil || acl.Grants != nil
	t.DefaultSrcPosture = acl.DefaultSourcePosture
	for _, g := range acl.Grants {
		t.Grants = append(t.Grants, &tailnet.Grant{
			Sources: g.Source, Destinations: g.Destination, IP: g.IP,
			App: g.App, SrcPosture: g.SrcPosture, Via: g.Via,
		})
	}
	for _, e := range acl.ACLs {
		if !strings.EqualFold(e.Action, "accept") {
			continue
		}
		sources, destinations := e.Source, e.Destination
		if sources == nil {
			sources = e.Users
		}
		if destinations == nil {
			destinations = e.Ports
		}
		t.Grants = append(t.Grants, &tailnet.Grant{
			Sources: sources, Destinations: destinations, Protocol: e.Protocol,
			SrcPosture: e.SourcePosture, Legacy: true,
		})
	}
}

// Package collector fetches data from the Tailscale API and normalizes it
// into a tailnet.Tailnet snapshot. This is the only package that talks to
// the Tailscale API.
package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/auth"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Collect gathers devices, users, and the policy file, returning a
// normalized tailnet snapshot.
func Collect(ctx context.Context) (*tailnet.Tailnet, error) {
	creds, _, err := auth.Resolve()
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, fmt.Errorf("not authenticated: set TS_ACCESS_TOKEN or run `taildoc auth login`; create an API key at https://login.tailscale.com/admin/settings/keys")
	}

	client, err := auth.Client(creds)
	if err != nil {
		return nil, err
	}

	t := &tailnet.Tailnet{
		Name:        creds.Tailnet,
		CollectedAt: time.Now(),
		Groups:      map[string][]string{},
		TagOwners:   map[string][]string{},
		Hosts:       map[string]string{},
		Postures:    map[string][]string{},
	}

	if err := collectUsers(ctx, client, t); err != nil {
		return nil, err
	}
	if err := collectDevices(ctx, client, t); err != nil {
		return nil, err
	}
	if err := collectPolicy(ctx, client, t); err != nil {
		return nil, err
	}

	return t, nil
}

func collectUsers(ctx context.Context, c *tailscale.Client, t *tailnet.Tailnet) error {
	users, err := c.Users().List(ctx, nil, nil)
	if err != nil {
		return fmt.Errorf("listing users (token may lack user read scope or admin role): %w", err)
	}
	for _, u := range users {
		t.Users = append(t.Users, &tailnet.User{
			ID:                 u.ID,
			LoginName:          u.LoginName,
			DisplayName:        u.DisplayName,
			Role:               string(u.Role),
			Status:             string(u.Status),
			Type:               string(u.Type),
			Created:            u.Created,
			LastSeen:           u.LastSeen,
			CurrentlyConnected: u.CurrentlyConnected,
			DeviceCount:        u.DeviceCount,
		})
	}
	return nil
}

func collectDevices(ctx context.Context, c *tailscale.Client, t *tailnet.Tailnet) error {
	devices, err := c.Devices().ListWithAllFields(ctx)
	if err != nil {
		return fmt.Errorf("listing devices (token may lack device read scope or admin role): %w", err)
	}
	for _, d := range devices {
		dev := &tailnet.Device{
			ID:                        d.ID,
			NodeID:                    d.NodeID,
			Name:                      d.Name,
			Hostname:                  d.Hostname,
			OS:                        d.OS,
			ClientVersion:             d.ClientVersion,
			Owner:                     d.User,
			Tags:                      d.Tags,
			Addresses:                 d.Addresses,
			AdvertisedRoutes:          d.AdvertisedRoutes,
			EnabledRoutes:             d.EnabledRoutes,
			Online:                    d.ConnectedToControl,
			Authorized:                d.Authorized,
			KeyExpiryDisabled:         d.KeyExpiryDisabled,
			BlocksIncomingConnections: d.BlocksIncomingConnections,
			UpdateAvailable:           d.UpdateAvailable,
			IsEphemeral:               d.IsEphemeral,
			IsExternal:                d.IsExternal,
			SSHEnabled:                d.SSHEnabled,
			Created:                   d.Created.Time,
		}
		if d.LastSeen != nil {
			dev.LastSeen = d.LastSeen.Time
		}
		if !d.Expires.IsZero() {
			dev.Expires = d.Expires.Time
		}
		t.Devices = append(t.Devices, dev)
	}
	return nil
}

func collectPolicy(ctx context.Context, c *tailscale.Client, t *tailnet.Tailnet) error {
	acl, err := c.PolicyFile().Get(ctx)
	if err != nil {
		return fmt.Errorf("reading policy file (token may lack policy read scope or admin role): %w", err)
	}

	for g, members := range acl.Groups {
		t.Groups[g] = members
	}
	for tag, owners := range acl.TagOwners {
		t.TagOwners[normalizeTag(tag)] = owners
	}
	for h, ip := range acl.Hosts {
		t.Hosts[h] = ip
	}
	for p, conds := range acl.Postures {
		t.Postures[p] = conds
	}
	if acl.AutoApprovers != nil {
		t.AutoApprovers = tailnet.AutoApprovers{
			Routes:   acl.AutoApprovers.Routes,
			ExitNode: acl.AutoApprovers.ExitNode,
			Services: acl.AutoApprovers.Services,
		}
	}
	t.HasAccessRules = acl.ACLs != nil || acl.Grants != nil
	t.DefaultSrcPosture = acl.DefaultSourcePosture

	// Modern grants.
	for _, g := range acl.Grants {
		t.Grants = append(t.Grants, &tailnet.Grant{
			Sources:      g.Source,
			Destinations: g.Destination,
			IP:           g.IP,
			App:          g.App,
			SrcPosture:   g.SrcPosture,
			Via:          g.Via,
		})
	}

	// Legacy ACLs, normalized into Grant shape.
	for _, e := range acl.ACLs {
		if strings.ToLower(e.Action) == "deny" {
			continue // deny entries are not part of the MVP evaluator
		}
		g := &tailnet.Grant{
			Sources:      e.Source,
			Destinations: e.Destination,
			Legacy:       true,
		}
		for _, p := range e.Ports {
			g.IP = append(g.IP, normalizeLegacyPort(p, e.Protocol))
		}
		t.Grants = append(t.Grants, g)
	}

	return nil
}

func normalizeTag(tag string) string {
	if !strings.Contains(tag, ":") {
		return "tag:" + tag
	}
	return tag
}

// normalizeLegacyPort converts legacy ACL "ports" ("5432", "5432:5434") plus
// optional proto into grant-style IP entries ("tcp:5432").
func normalizeLegacyPort(port, proto string) string {
	switch proto {
	case "", "tcp":
		return "tcp:" + port
	case "udp":
		return "udp:" + port
	default:
		return proto + ":" + port
	}
}

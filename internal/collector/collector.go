// Package collector fetches data from the Tailscale API and normalizes it
// into a tailnet.Tailnet snapshot. This is the only package that talks to
// the Tailscale API.
package collector

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/auth"
	"github.com/huza1fa/taildoc/internal/policy"
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
	return collectFrom(ctx, client, creds.Tailnet)
}

func collectFrom(ctx context.Context, client *tailscale.Client, name string) (*tailnet.Tailnet, error) {
	t := &tailnet.Tailnet{
		Name:        name,
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

	// Credentials scoped to the three reads above must keep working, so these
	// only narrow the audit and are reported rather than failing the collection.
	if err := collectAuthKeys(ctx, client, t); err != nil {
		t.CollectionGaps = append(t.CollectionGaps, "auth keys: "+err.Error())
	}
	if err := collectSettings(ctx, client, t); err != nil {
		t.CollectionGaps = append(t.CollectionGaps, "tailnet settings: "+err.Error())
	}
	if err := ctx.Err(); err != nil {
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
	devices, err := c.Devices().List(ctx, tailscale.WithFields(tailscale.IncludeFieldsAll))
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
		// The API reports who registered a tagged device; tags replace that
		// identity, so the device has no owner.
		if len(d.Tags) > 0 {
			dev.Owner = ""
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

	policy.Normalize(t, acl)
	return nil
}

// collectAuthKeys fetches each key individually because the list endpoint
// returns identifiers only. The secret is never copied into the snapshot.
func collectAuthKeys(ctx context.Context, c *tailscale.Client, t *tailnet.Tailnet) error {
	keys, err := c.Keys().List(ctx, true)
	if err != nil {
		return err
	}
	for _, listed := range keys {
		k, err := c.Keys().Get(ctx, listed.ID)
		if err != nil {
			return err
		}
		if (k.KeyType != "" && k.KeyType != "auth") || k.Invalid || !k.Revoked.IsZero() {
			continue
		}
		create := k.Capabilities.Devices.Create
		t.AuthKeys = append(t.AuthKeys, &tailnet.AuthKey{
			ID: k.ID, Description: k.Description, Created: k.Created, Expires: k.Expires,
			Reusable: create.Reusable, Ephemeral: create.Ephemeral,
			Preauthorized: create.Preauthorized, Tags: create.Tags,
		})
	}
	return nil
}

func collectSettings(ctx context.Context, c *tailscale.Client, t *tailnet.Tailnet) error {
	s, err := c.TailnetSettings().Get(ctx)
	if err != nil {
		return err
	}
	t.Settings = &tailnet.Settings{
		DevicesApprovalOn:      s.DevicesApprovalOn,
		UsersApprovalOn:        s.UsersApprovalOn,
		DevicesAutoUpdatesOn:   s.DevicesAutoUpdatesOn,
		DevicesKeyDurationDays: s.DevicesKeyDurationDays,
	}
	return nil
}

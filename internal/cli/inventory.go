package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runInventory(ctx context.Context, args []string) error {
	fs := newFlagSet("inventory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := collect(ctx)
	if err != nil {
		return err
	}

	printUsers(t)
	printGroups(t)
	printDevices(t)
	printTagOwners(t)
	printGrants(t)
	printRouters(t)
	return nil
}

func printUsers(t *tailnet.Tailnet) {
	fmt.Printf("Users (%d)\n", len(t.Users))
	for _, u := range sortUsers(t.Users) {
		marker := ""
		if tailnet.CanManage(u.Role) {
			marker = "  [manages tailnet]"
		}
		fmt.Printf("  %-40s %-14s %-10s %d device(s)%s\n",
			u.LoginName, u.Role, u.Status, u.DeviceCount, marker)
	}
	fmt.Println()
}

func printGroups(t *tailnet.Tailnet) {
	if len(t.Groups) == 0 {
		fmt.Println("Groups (0)")
		fmt.Println()
		return
	}
	names := sortedKeys(t.Groups)
	fmt.Printf("Groups (%d)\n", len(names))
	for _, g := range names {
		members := t.Groups[g]
		fmt.Printf("  %s (%d member%s)\n", g, len(members), plural(len(members)))
		for _, m := range members {
			fmt.Printf("    %s\n", m)
		}
	}
	fmt.Println()
}

func printDevices(t *tailnet.Tailnet) {
	fmt.Printf("Devices (%d)\n", len(t.Devices))
	for _, d := range t.Devices {
		status := "offline"
		if d.Online {
			status = "online"
		}
		owner := d.Owner
		if owner == "" && len(d.Tags) > 0 {
			owner = strings.Join(d.Tags, ",")
		}
		fmt.Printf("  %-32s %-8s %-10s %-8s owner: %s\n",
			d.Hostname, d.OS, orDefault(d.ClientVersion, "?"), status, orDefault(owner, "-"))

		if groups := groupsForDeviceOwner(t, d); len(groups) > 0 {
			fmt.Printf("      groups: %s\n", strings.Join(groups, ", "))
		}
		if len(d.Addresses) > 0 {
			fmt.Printf("      addresses: %s\n", strings.Join(d.Addresses, ", "))
		}
		if len(d.AdvertisedRoutes) > 0 || len(d.EnabledRoutes) > 0 {
			fmt.Printf("      routes: advertises [%s], enabled [%s]\n",
				strings.Join(d.AdvertisedRoutes, ", "), strings.Join(d.EnabledRoutes, ", "))
		}
		if !d.Expires.IsZero() {
			until := time.Until(d.Expires)
			if d.KeyExpiryDisabled {
				fmt.Printf("      key expiry: disabled\n")
			} else if until < 30*24*time.Hour && until > 0 {
				fmt.Printf("      key expires in %s\n", durationDays(until))
			} else if until <= 0 {
				fmt.Printf("      key EXPIRED\n")
			}
		}
	}
	fmt.Println()
}

func printTagOwners(t *tailnet.Tailnet) {
	if len(t.TagOwners) == 0 {
		return
	}
	names := sortedKeys(t.TagOwners)
	fmt.Printf("Tag ownership (%d)\n", len(names))
	for _, tag := range names {
		fmt.Printf("  %s owned by: %s\n", tag, strings.Join(t.TagOwners[tag], ", "))
	}
	fmt.Println()
}

func printGrants(t *tailnet.Tailnet) {
	kind := "grants"
	fmt.Printf("Policy grants (%d)\n", len(t.Grants))
	for _, g := range t.Grants {
		label := "grant"
		if g.Legacy {
			label = "legacy acl"
		}
		fmt.Printf("  [%s] %s -> %s via %s\n",
			label,
			strings.Join(g.Sources, ", "),
			strings.Join(g.Destinations, ", "),
			orDefault(strings.Join(g.IP, ", "), "(all ip)"))
		if len(g.SrcPosture) > 0 {
			fmt.Printf("        posture: %s\n", strings.Join(g.SrcPosture, ", "))
		}
	}
	_ = kind
	fmt.Println()
}

func printRouters(t *tailnet.Tailnet) {
	var exitNodes, subnetRouters []*tailnet.Device
	for _, d := range t.Devices {
		isExit := false
		for _, r := range d.AdvertisedRoutes {
			if r == "0.0.0.0/0" || r == "::/0" {
				isExit = true
			}
		}
		if isExit {
			exitNodes = append(exitNodes, d)
		} else if len(d.AdvertisedRoutes) > 0 {
			subnetRouters = append(subnetRouters, d)
		}
	}

	fmt.Printf("Exit nodes (%d), subnet routers (%d)\n", len(exitNodes), len(subnetRouters))
	for _, d := range exitNodes {
		fmt.Printf("  exit node: %s (enabled routes: %s)\n", d.Hostname, routeSummary(d))
	}
	for _, d := range subnetRouters {
		fmt.Printf("  subnet router: %s advertises [%s], enabled [%s]\n",
			d.Hostname,
			strings.Join(d.AdvertisedRoutes, ", "),
			strings.Join(d.EnabledRoutes, ", "))
	}
	if approvers := t.AutoApprovers.ExitNode; len(approvers) > 0 {
		fmt.Printf("  auto-approved exit node owners: %s\n", strings.Join(approvers, ", "))
	}
	fmt.Println()
}

// groupsForDeviceOwner returns the groups of a device's owning user.
func groupsForDeviceOwner(t *tailnet.Tailnet, d *tailnet.Device) []string {
	if d.Owner == "" {
		return nil
	}
	groups := t.GroupsOfUser(d.Owner)
	sort.Strings(groups)
	return groups
}

func sortUsers(users []*tailnet.User) []*tailnet.User {
	out := append([]*tailnet.User(nil), users...)
	sort.Slice(out, func(i, j int) bool { return out[i].LoginName < out[j].LoginName })
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func durationDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days <= 0 {
		return "<1 day"
	}
	return fmt.Sprintf("%dd", days)
}

func routeSummary(d *tailnet.Device) string {
	if len(d.EnabledRoutes) == 0 {
		return "none enabled"
	}
	return strings.Join(d.EnabledRoutes, ", ")
}

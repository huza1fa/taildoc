package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// searchResult is one navigable tailnet resource returned by find.
type searchResult struct {
	Kind        string
	Name        string
	Ref         string
	Description string
	Score       int
}

func runFind(ctx context.Context, args []string) error {
	fs := newFlagSet("find")
	snapshotPath := fs.String("snapshot", "", "search a saved snapshot instead of collecting live data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || strings.TrimSpace(fs.Arg(0)) == "" {
		return fmt.Errorf("usage: taildoc find <query> [--snapshot FILE]")
	}

	t, err := loadTailnet(ctx, *snapshotPath)
	if err != nil {
		return err
	}
	results := findTailnet(t, fs.Arg(0))
	if len(results) == 0 {
		fmt.Printf("No tailnet resources match %q. Try a hostname, IP, user, tag, group, or host alias.\n", fs.Arg(0))
		return nil
	}

	fmt.Printf("Matches for %q (%d)\n", fs.Arg(0), len(results))
	for _, result := range results {
		fmt.Printf("  %-7s %-28s %s\n", result.Kind, result.Name, result.Description)
	}
	fmt.Println()
	fmt.Printf("Details: taildoc show %s\n", results[0].Ref)
	if results[0].Kind == "device" || results[0].Kind == "host" || results[0].Kind == "tag" {
		fmt.Printf("Policy path: taildoc explain <source> %s[:port]\n", results[0].Ref)
	}
	return nil
}

func runShow(ctx context.Context, args []string) error {
	fs := newFlagSet("show")
	snapshotPath := fs.String("snapshot", "", "show a resource from a saved snapshot instead of collecting live data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || strings.TrimSpace(fs.Arg(0)) == "" {
		return fmt.Errorf("usage: taildoc show <resource> [--snapshot FILE]")
	}

	t, err := loadTailnet(ctx, *snapshotPath)
	if err != nil {
		return err
	}
	ref := fs.Arg(0)
	if d := t.FindDevice(ref); d != nil {
		printDeviceDetail(t, d)
		return nil
	}
	if u := t.FindUser(ref); u != nil {
		printUserDetail(t, u)
		return nil
	}
	if ip, ok := t.Hosts[ref]; ok {
		printHostDetail(t, ref, ip)
		return nil
	}
	if tagExists(t, ref) {
		printTagDetail(t, ref)
		return nil
	}
	if members, ok := t.Groups[ref]; ok {
		printGroupDetail(t, ref, members)
		return nil
	}
	return fmt.Errorf("cannot resolve %q; use 'taildoc find %s' to search", ref, ref)
}

func loadTailnet(ctx context.Context, snapshotPath string) (*tailnet.Tailnet, error) {
	if snapshotPath != "" {
		return snapshot.Load(snapshotPath)
	}
	return collect(ctx)
}

// findTailnet returns substring and subsequence matches. Substrings are ranked
// first, but fuzzy matching makes short exploratory queries useful too.
func findTailnet(t *tailnet.Tailnet, query string) []searchResult {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	var results []searchResult
	for _, d := range t.Devices {
		fields := append([]string{d.Hostname, d.Name, d.Owner}, d.Addresses...)
		fields = append(fields, d.Tags...)
		if score := matchScore(query, fields...); score > 0 {
			bits := []string{onlineLabel(d), orDefault(d.OS, "unknown OS")}
			if len(d.Addresses) > 0 {
				bits = append(bits, d.Addresses[0])
			}
			if d.Owner != "" {
				bits = append(bits, "owner "+d.Owner)
			} else if len(d.Tags) > 0 {
				bits = append(bits, strings.Join(d.Tags, ", "))
			}
			results = append(results, searchResult{"device", d.Hostname, d.Hostname, strings.Join(bits, " · "), score})
		}
	}
	for _, u := range t.Users {
		if score := matchScore(query, u.LoginName, u.DisplayName); score > 0 {
			bits := []string{orDefault(u.DisplayName, u.Role), u.Status}
			if u.DeviceCount > 0 {
				bits = append(bits, fmt.Sprintf("%d device%s", u.DeviceCount, plural(u.DeviceCount)))
			}
			results = append(results, searchResult{"user", u.LoginName, u.LoginName, strings.Join(bits, " · "), score})
		}
	}
	for _, tag := range allTags(t) {
		if score := matchScore(query, tag, strings.Join(t.TagOwners[tag], " ")); score > 0 {
			bits := []string{fmt.Sprintf("%d device%s", len(t.DevicesWithTag(tag)), plural(len(t.DevicesWithTag(tag))))}
			if owners := t.TagOwners[tag]; len(owners) > 0 {
				bits = append(bits, "owners "+strings.Join(owners, ", "))
			}
			results = append(results, searchResult{"tag", tag, tag, strings.Join(bits, " · "), score})
		}
	}
	for group, members := range t.Groups {
		if score := matchScore(query, group, strings.Join(members, " ")); score > 0 {
			desc := fmt.Sprintf("%d member%s", len(members), plural(len(members)))
			if len(members) > 0 {
				desc += " · " + strings.Join(members[:min(2, len(members))], ", ")
			}
			results = append(results, searchResult{"group", group, group, desc, score})
		}
	}
	for host, ip := range t.Hosts {
		if score := matchScore(query, host, ip); score > 0 {
			desc := "→ " + ip
			if d := t.FindDevice(ip); d != nil {
				desc += " · " + d.Hostname
			}
			results = append(results, searchResult{"host", host, host, desc, score})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].Kind != results[j].Kind {
			return results[i].Kind < results[j].Kind
		}
		return results[i].Name < results[j].Name
	})
	return results
}

func matchScore(query string, values ...string) int {
	best := 0
	for _, value := range values {
		value = strings.ToLower(value)
		switch {
		case value == query:
			best = max(best, 400)
		case strings.HasPrefix(value, query):
			best = max(best, 300)
		case strings.Contains(value, query):
			best = max(best, 200)
		case fuzzyMatch(query, value):
			best = max(best, 100)
		}
	}
	return best
}

func fuzzyMatch(query, value string) bool {
	if len(query) < 2 {
		return false
	}
	pos := 0
	for _, r := range value {
		if pos < len(query) && byte(r) == query[pos] {
			pos++
		}
	}
	return pos == len(query)
}

func allTags(t *tailnet.Tailnet) []string {
	set := make(map[string]bool, len(t.TagOwners))
	for tag := range t.TagOwners {
		set[tag] = true
	}
	for _, d := range t.Devices {
		for _, tag := range d.Tags {
			set[tag] = true
		}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func tagExists(t *tailnet.Tailnet, tag string) bool {
	for _, candidate := range allTags(t) {
		if candidate == tag {
			return true
		}
	}
	return false
}

func onlineLabel(d *tailnet.Device) string {
	if d.Online {
		return "online"
	}
	return "offline"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printDeviceDetail(t *tailnet.Tailnet, d *tailnet.Device) {
	fmt.Printf("Device: %s (%s)\n\n", d.Hostname, onlineLabel(d))
	fmt.Printf("  OS:        %s\n", orDefault(d.OS, "-"))
	fmt.Printf("  Addresses: %s\n", orDefault(strings.Join(d.Addresses, ", "), "-"))
	fmt.Printf("  Owner:     %s\n", orDefault(d.Owner, "(tagged device)"))
	fmt.Printf("  Tags:      %s\n", orDefault(strings.Join(d.Tags, ", "), "-"))
	if groups := groupsForDeviceOwner(t, d); len(groups) > 0 {
		fmt.Printf("  Groups:    %s\n", strings.Join(groups, ", "))
	}
	if len(d.AdvertisedRoutes) > 0 || len(d.EnabledRoutes) > 0 {
		fmt.Printf("  Routes:    advertises [%s], enabled [%s]\n", orDefault(strings.Join(d.AdvertisedRoutes, ", "), "-"), orDefault(strings.Join(d.EnabledRoutes, ", "), "-"))
	}
	printRelatedGrants(t, append(append([]string{d.Owner}, d.Tags...), d.Addresses...))
	fmt.Printf("\nTry: taildoc explain <source> %s[:port]\n", d.Hostname)
}

func printUserDetail(t *tailnet.Tailnet, u *tailnet.User) {
	fmt.Printf("User: %s\n\n", u.LoginName)
	fmt.Printf("  Name:    %s\n", orDefault(u.DisplayName, "-"))
	fmt.Printf("  Role:    %s\n", orDefault(u.Role, "-"))
	fmt.Printf("  Status:  %s\n", orDefault(u.Status, "-"))
	if groups := t.GroupsOfUser(u.LoginName); len(groups) > 0 {
		sort.Strings(groups)
		fmt.Printf("  Groups:  %s\n", strings.Join(groups, ", "))
	}
	var devices []string
	for _, d := range t.Devices {
		if d.Owner == u.LoginName {
			devices = append(devices, d.Hostname)
		}
	}
	sort.Strings(devices)
	fmt.Printf("  Devices: %s\n", orDefault(strings.Join(devices, ", "), "-"))
	printRelatedGrants(t, append([]string{u.LoginName}, t.GroupsOfUser(u.LoginName)...))
	fmt.Printf("\nTry: taildoc explain %s <destination[:port]>\n", u.LoginName)
}

func printTagDetail(t *tailnet.Tailnet, tag string) {
	fmt.Printf("Tag: %s\n\n", tag)
	fmt.Printf("  Owners:  %s\n", orDefault(strings.Join(t.TagOwners[tag], ", "), "-"))
	devices := t.DevicesWithTag(tag)
	var names []string
	for _, d := range devices {
		names = append(names, d.Hostname+" ("+onlineLabel(d)+")")
	}
	sort.Strings(names)
	fmt.Printf("  Devices: %s\n", orDefault(strings.Join(names, ", "), "-"))
	printRelatedGrants(t, []string{tag})
	fmt.Printf("\nTry: taildoc explain <source> %s[:port]\n", tag)
}

func printGroupDetail(t *tailnet.Tailnet, group string, members []string) {
	fmt.Printf("Group: %s\n\n", group)
	fmt.Printf("  Members: %s\n", orDefault(strings.Join(members, ", "), "-"))
	printRelatedGrants(t, []string{group})
	fmt.Printf("\nTry: taildoc explain %s <destination[:port]>\n", group)
}

func printHostDetail(t *tailnet.Tailnet, host, ip string) {
	fmt.Printf("Host alias: %s\n\n  Address: %s\n", host, ip)
	if d := t.FindDevice(ip); d != nil {
		fmt.Printf("  Device:  %s\n\nTry: taildoc show %s\n", d.Hostname, d.Hostname)
	}
}

func printRelatedGrants(t *tailnet.Tailnet, selectors []string) {
	var matching []*tailnet.Grant
	for _, g := range t.Grants {
		if grantMentions(g, selectors) {
			matching = append(matching, g)
		}
	}
	if len(matching) == 0 {
		return
	}
	fmt.Printf("  Policy:  %d related grant%s\n", len(matching), plural(len(matching)))
	for _, g := range matching[:min(3, len(matching))] {
		fmt.Printf("           %s → %s\n", strings.Join(g.Sources, ", "), strings.Join(g.Destinations, ", "))
	}
	if len(matching) > 3 {
		fmt.Printf("           … and %d more\n", len(matching)-3)
	}
}

func grantMentions(g *tailnet.Grant, selectors []string) bool {
	for _, selector := range selectors {
		if selector == "" {
			continue
		}
		for _, value := range append(append([]string{}, g.Sources...), g.Destinations...) {
			if value == selector || strings.HasPrefix(value, selector+":") {
				return true
			}
		}
	}
	return false
}

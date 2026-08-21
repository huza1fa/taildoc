package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runExplain(ctx context.Context, args []string) error {
	fs := newFlagSet("explain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: taildoc explain <source> <destination[:port]>")
	}

	t, err := collect(ctx)
	if err != nil {
		return err
	}

	srcRef, dstRef := rest[0], rest[1]

	srcDev, srcUser := resolveSource(t, srcRef)
	if srcDev == nil && srcUser == nil {
		return fmt.Errorf("cannot resolve source %q: no device or user matches", srcRef)
	}

	dstHost, dstPort := splitDestPort(dstRef)
	dstDev, dstTag := resolveDestination(t, dstHost)
	if dstDev == nil && dstTag == "" {
		return fmt.Errorf("cannot resolve destination %q: no device, tag, or host alias matches", dstHost)
	}

	req := buildRequest(t, srcDev, srcUser, dstDev, dstTag, dstPort)
	printExplain(t, srcDev, srcUser, dstDev, dstTag, req)

	result := policy.Evaluate(t, req)
	printResult(result, dstPort)
	return nil
}

// resolveSource finds a device by hostname/IP/name, falling back to a user.
func resolveSource(t *tailnet.Tailnet, ref string) (*tailnet.Device, *tailnet.User) {
	if d := t.FindDevice(ref); d != nil {
		return d, nil
	}
	if u := t.FindUser(ref); u != nil {
		return nil, u
	}
	return nil, nil
}

// splitDestPort separates "postgres-prod:5432" into ("postgres-prod", "5432").
func splitDestPort(ref string) (host, port string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ref, ""
	}
	p := ref[i+1:]
	if p != "*" && !isNumeric(p) {
		return ref, ""
	}
	return ref[:i], p
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// resolveDestination resolves a host reference to a device or a tag.
func resolveDestination(t *tailnet.Tailnet, host string) (*tailnet.Device, string) {
	if strings.HasPrefix(host, "tag:") {
		devs := t.DevicesWithTag(host)
		if len(devs) > 0 {
			return devs[0], host
		}
		return nil, host // tag exists as a selector even without devices
	}
	if d := t.FindDevice(host); d != nil {
		return d, ""
	}
	if ip, ok := t.Hosts[host]; ok {
		if d := t.FindDevice(ip); d != nil {
			return d, ""
		}
	}
	return nil, ""
}

func buildRequest(t *tailnet.Tailnet, srcDev *tailnet.Device, srcUser *tailnet.User, dstDev *tailnet.Device, dstTag, port string) policy.Request {
	req := policy.Request{Port: port}

	switch {
	case srcDev != nil:
		req.SourceTags = srcDev.Tags
		req.SourceLogin = srcDev.Owner
	case srcUser != nil:
		req.SourceLogin = srcUser.LoginName
	}

	if dstDev != nil {
		req.DestTags = dstDev.Tags
		req.DestIPs = dstDev.Addresses
		req.DestOwner = dstDev.Owner
	} else if dstTag != "" {
		for _, d := range t.DevicesWithTag(dstTag) {
			req.DestIPs = append(req.DestIPs, d.Addresses...)
			req.DestTags = append(req.DestTags, d.Tags...)
		}
		req.DestTags = append(req.DestTags, dstTag)
	}
	return req
}

func printExplain(t *tailnet.Tailnet, srcDev *tailnet.Device, srcUser *tailnet.User, dstDev *tailnet.Device, dstTag string, req policy.Request) {
	fmt.Println("Source")
	if srcDev != nil {
		fmt.Printf("  %s (%s)\n", srcDev.Hostname, srcDev.OS)
		fmt.Printf("  owner: %s\n", orDefault(srcDev.Owner, "(tagged device, no user owner)"))
		if groups := t.GroupsOfUser(srcDev.Owner); len(groups) > 0 {
			fmt.Printf("  groups: %s\n", strings.Join(groups, ", "))
		}
		if len(srcDev.Tags) > 0 {
			fmt.Printf("  tags: %s\n", strings.Join(srcDev.Tags, ", "))
		}
	} else {
		u := srcUser
		fmt.Printf("  %s\n", u.LoginName)
		fmt.Printf("  role: %s\n", u.Role)
		if groups := t.GroupsOfUser(u.LoginName); len(groups) > 0 {
			fmt.Printf("  groups: %s\n", strings.Join(groups, ", "))
		}
	}
	fmt.Println()

	fmt.Println("Destination")
	if dstDev != nil {
		fmt.Printf("  %s (%s)\n", dstDev.Hostname, dstDev.OS)
		if len(dstDev.Tags) > 0 {
			fmt.Printf("  tags: %s\n", strings.Join(dstDev.Tags, ", "))
		} else {
			fmt.Printf("  owner: %s\n", orDefault(dstDev.Owner, "-"))
		}
		fmt.Printf("  addresses: %s\n", strings.Join(dstDev.Addresses, ", "))
	} else {
		fmt.Printf("  %s (no devices currently carry this tag)\n", dstTag)
	}
	fmt.Println()
}

func printResult(result policy.Result, port string) {
	fmt.Println("Access path")
	if result.Allowed {
		for i, m := range result.Matches {
			if i > 0 {
				fmt.Println()
			}
			g := m.Grant
			kind := "grant"
			if g.Legacy {
				kind = "legacy acl"
			}
			fmt.Printf("  via %s:\n", kind)
			fmt.Printf("    src: %s\n", strings.Join(g.Sources, ", "))
			fmt.Printf("    dst: %s\n", strings.Join(g.Destinations, ", "))
			fmt.Printf("    ip:  %s\n", orDefault(strings.Join(g.IP, ", "), "(all)"))
			for _, c := range m.Chain {
				fmt.Printf("    - %s\n", c)
			}
		}
		fmt.Println()
		fmt.Println("Result: ACCESS ALLOWED")
	} else {
		fmt.Println("  (no grant produces an allow path)")
		fmt.Println()
		fmt.Println("Result: ACCESS DENIED")
		fmt.Println()
		fmt.Println("The chain fails at policy matching: no grant's source and destination")
		fmt.Println("selectors both cover this pair for the requested port.")
	}

	if len(result.Unsupported) > 0 {
		fmt.Println()
		fmt.Println("Notes (Taildoc could not fully evaluate these):")
		seen := map[string]bool{}
		for _, u := range result.Unsupported {
			if seen[u.Selector] {
				continue
			}
			seen[u.Selector] = true
			fmt.Printf("  - %s: %s\n", u.Selector, u.Reason)
		}
	}

	if port != "" && port != "*" {
		fmt.Println()
		fmt.Printf("Note: control-plane data cannot show whether anything is actually\nlistening on port %s. Taildoc evaluates policy only.\n", port)
	}
}

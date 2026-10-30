package policy

import (
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func testTailnet() *tailnet.Tailnet {
	return &tailnet.Tailnet{
		Users: []*tailnet.User{
			{LoginName: "alice@example.com", Role: "member"},
			{LoginName: "bob@example.com", Role: "owner"},
		},
		Groups: map[string][]string{
			"group:engineering": {"alice@example.com"},
		},
		TagOwners: map[string][]string{
			"tag:prod": {"bob@example.com"},
		},
		HasAccessRules: true,
		Devices: []*tailnet.Device{
			{Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
			{Hostname: "db-prod", Tags: []string{"tag:prod"}, Addresses: []string{"100.64.0.2"}},
			{Hostname: "web-01", Tags: []string{"tag:web"}, Addresses: []string{"100.64.0.3"}},
		},
		Grants: []*tailnet.Grant{
			{Sources: []string{"group:engineering"}, Destinations: []string{"tag:prod:5432"}, IP: []string{"tcp:5432"}},
			{Sources: []string{"bob@example.com"}, Destinations: []string{"*:*"}, Legacy: true},
			{Sources: []string{"tag:web"}, Destinations: []string{"tag:prod:80"}, IP: []string{"tcp:80"}},
		},
	}
}

func TestEvaluateGroupToTagAllowed(t *testing.T) {
	res := Evaluate(testTailnet(), Request{
		SourceLogin: "alice@example.com",
		DestTags:    []string{"tag:prod"},
		DestIPs:     []string{"100.64.0.2"},
		Port:        "5432",
		Proto:       "tcp",
	})
	if !res.Allowed {
		t.Fatalf("expected allowed, got denied: %+v", res)
	}
}

func TestEvaluateWrongPortDenied(t *testing.T) {
	res := Evaluate(testTailnet(), Request{
		SourceLogin: "alice@example.com",
		DestTags:    []string{"tag:prod"},
		DestIPs:     []string{"100.64.0.2"},
		Port:        "22",
	})
	if res.Allowed {
		t.Fatal("expected denied on port 22, got allowed")
	}
}

func TestEvaluateUnrelatedUserDenied(t *testing.T) {
	res := Evaluate(testTailnet(), Request{
		SourceLogin: "mallory@example.com",
		DestTags:    []string{"tag:prod"},
		DestIPs:     []string{"100.64.0.2"},
		Port:        "5432",
	})
	if res.Allowed {
		t.Fatal("expected denied for unrelated user, got allowed")
	}
}

func TestEvaluateWildcardOwnerAllowed(t *testing.T) {
	res := Evaluate(testTailnet(), Request{
		SourceLogin: "bob@example.com",
		DestTags:    []string{"tag:web"},
		DestIPs:     []string{"100.64.0.3"},
		Port:        "9999",
	})
	if !res.Allowed {
		t.Fatalf("expected owner wildcard grant to allow, got denied: %+v", res)
	}
}

func TestEvaluateTaggedDeviceSource(t *testing.T) {
	res := Evaluate(testTailnet(), Request{
		SourceTags: []string{"tag:web"},
		DestTags:   []string{"tag:prod"},
		DestIPs:    []string{"100.64.0.2"},
		Port:       "80",
	})
	if !res.Allowed {
		t.Fatalf("expected tag:web -> tag:prod:80 allowed, got denied: %+v", res)
	}
}

func TestSplitDst(t *testing.T) {
	cases := []struct {
		in, host, port string
	}{
		{"tag:prod:5432", "tag:prod", "5432"},
		{"*", "*", "*"},
		{"10.0.0.0/24", "10.0.0.0/24", "*"},
		{"host.example.com:443", "host.example.com", "443"},
		{"autogroup:self", "autogroup:self", "*"},
		{"tag:22", "tag:22", "*"},
		{"tag:22:443", "tag:22", "443"},
		{"ipset:123", "ipset:123", "*"},
		{"group:123", "group:123", "*"},
		{"svc:123", "svc:123", "*"},
		{"100.64.0.1", "100.64.0.1", "*"},
		{"::1", "::1", "*"},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1", "*"},
		{"2001:db8::/32", "2001:db8::/32", "*"},
		{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::1", "*"},
		{"[fd7a:115c:a1e0::1]:443", "fd7a:115c:a1e0::1", "443"},
	}
	for _, c := range cases {
		host, port, ok := splitDst(c.in)
		if !ok || host != c.host || port != c.port {
			t.Errorf("splitDst(%q) = (%q, %q), want (%q, %q)", c.in, host, port, c.host, c.port)
		}
	}
}

func TestEvaluateHostAlias(t *testing.T) {
	tn := testTailnet()
	tn.Hosts = map[string]string{"db": "100.64.0.2"}
	tn.Grants = []*tailnet.Grant{{Sources: []string{"group:engineering"}, Destinations: []string{"db:5432"}, IP: []string{"tcp:5432"}}}
	if !Evaluate(tn, Request{SourceLogin: "alice@example.com", DestIPs: []string{"100.64.0.2"}, Port: "5432", Proto: "tcp"}).Allowed {
		t.Fatal("expected host alias to match")
	}
}

func TestEvaluateTaggedWildcardSource(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"tag:prod:443"}, IP: []string{"tcp:443"}}}
	if !Evaluate(tn, Request{SourceTags: []string{"tag:web"}, DestTags: []string{"tag:prod"}, Port: "443", Proto: "tcp"}).Allowed {
		t.Fatal("expected wildcard source to include tagged devices")
	}
}

func TestEvaluateConditionalGrantIsIndeterminate(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Sources: []string{"group:engineering"}, Destinations: []string{"tag:prod:443"}, IP: []string{"tcp:443"}, SrcPosture: []string{"posture:trusted"}}}
	res := Evaluate(tn, Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:prod"}, Port: "443", Proto: "tcp"})
	if res.Allowed || !res.Indeterminate {
		t.Fatalf("want indeterminate result, got %+v", res)
	}
}

func TestEvaluateDefaultPolicy(t *testing.T) {
	tn := testTailnet()
	tn.Grants = nil
	tn.HasAccessRules = false
	res := Evaluate(tn, Request{})
	if !res.Allowed || !res.DefaultAllowed {
		t.Fatalf("want default allowed, got %+v", res)
	}
}

func TestSelectorSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst   string
		allowed, unknown bool
	}{
		{"source IP", "100.64.0.1", "100.64.0.2", true, false},
		{"source CIDR", "100.64.0.0/24", "100.64.0.2", true, false},
		{"source alias", "laptop-alias", "db-alias", true, false},
		{"destination user", "alice@example.com", "bob@example.com", true, false},
		{"destination group", "alice@example.com", "group:ops", true, false},
		{"IP set", "ipset:office", "ipset:office", true, false},
		{"unsupported source", "svc:future", "100.64.0.2", false, true},
		{"unsupported destination", "alice@example.com", "svc:future", false, true},
		{"irrelevant unsupported", "mallory@example.com", "svc:future", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tn := testTailnet()
			tn.Hosts = map[string]string{"laptop-alias": "100.64.0.1", "db-alias": "100.64.0.2"}
			tn.Groups["group:ops"] = []string{"bob@example.com"}
			tn.IPSets = map[string][]string{"ipset:office": {"100.64.0.0/24"}}
			tn.Grants = []*tailnet.Grant{{Sources: []string{tc.src}, Destinations: []string{tc.dst}, IP: []string{"tcp:443"}}}
			got := Evaluate(tn, Request{SourceLogin: "alice@example.com", SourceIPs: []string{"100.64.0.1"}, DestOwner: "bob@example.com", DestTags: []string{}, DestIPs: []string{"100.64.0.2"}, Port: "443", Proto: "6"})
			if got.Allowed != tc.allowed || got.Indeterminate != tc.unknown {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestTaggedDeviceDoesNotInheritOwner(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Sources: []string{"alice@example.com"}, Destinations: []string{"*"}, IP: []string{"*"}}}
	req := Between(&tailnet.Device{Owner: "alice@example.com", Tags: []string{"tag:web"}}, &tailnet.Device{}, "443", "tcp")
	if Evaluate(tn, req).Allowed {
		t.Fatal("tagged device inherited owner access")
	}
	req.SourceLogin = "alice@example.com"
	req.SourceTags = []string{"tag:web"}
	if Evaluate(tn, req).Allowed {
		t.Fatal("manually constructed request inherited owner access")
	}
}
func TestNetworkAndApplicationGrants(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"*"}, App: map[string][]map[string]any{"example/cap": {{}}}}}
	if got := Evaluate(tn, Request{Port: "443"}); got.Allowed || got.Indeterminate {
		t.Fatalf("app-only grant gave packet access: %+v", got)
	}
	tn.Grants[0].IP = []string{"443"}
	if !Evaluate(tn, Request{Port: "443"}).Allowed {
		t.Fatal("app capabilities restricted independent network grant")
	}
	tn.Grants[0].SrcPosture = []string{}
	tn.DefaultSrcPosture = []string{"posture:default"}
	if !Evaluate(tn, Request{Port: "443"}).Allowed {
		t.Fatal("explicit empty posture did not override default")
	}
}
func TestLegacyPortsAndRanges(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Legacy: true, Sources: []string{"*"}, Destinations: []string{"tag:prod:22,80-90"}}}
	for _, p := range []string{"22", "80", "90"} {
		if !Evaluate(tn, Request{DestTags: []string{"tag:prod"}, Port: p, Proto: "tcp"}).Allowed {
			t.Errorf("port %s denied", p)
		}
	}
	for _, p := range []string{"21", "23", "91", "443"} {
		if Evaluate(tn, Request{DestTags: []string{"tag:prod"}, Port: p, Proto: "tcp"}).Allowed {
			t.Errorf("port %s allowed", p)
		}
	}
}

func TestProtocolSemantics(t *testing.T) {
	for _, tc := range []struct {
		ip, port, proto string
		allowed         bool
	}{
		{"443", "443", "udp", true}, {"443", "443", "sctp", false},
		{"443", "0", "icmp", true}, {"udp:443", "443", "17", true},
		{"udp:443", "443", "tcp", false}, {"sctp:443", "443", "132", true},
		{"gre:*", "0", "47", true},
	} {
		tn := testTailnet()
		tn.Grants = []*tailnet.Grant{{Sources: []string{"alice@example.com"}, Destinations: []string{"tag:prod"}, IP: []string{tc.ip}}}
		got := Evaluate(tn, Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:prod"}, Port: tc.port, Proto: tc.proto})
		if got.Allowed != tc.allowed {
			t.Errorf("%s %s/%s: %+v", tc.ip, tc.proto, tc.port, got)
		}
	}
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Legacy: true, Protocol: "tcp", Sources: []string{"alice@example.com"}, Destinations: []string{"tag:prod:22"}}}
	got := Evaluate(tn, Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:prod"}, Port: "0", Proto: "icmp"})
	if !got.Allowed {
		t.Fatalf("ACL implicit ICMP: %+v", got)
	}
	tn.Grants[0].Protocol = "sctp"
	if !Evaluate(tn, Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:prod"}, Port: "22", Proto: "sctp"}).Allowed {
		t.Fatal("explicit SCTP ACL was denied")
	}
}
func TestUnsupportedAlternativesAndWildcardScope(t *testing.T) {
	tn := testTailnet()
	tn.Grants = []*tailnet.Grant{{Sources: []string{"svc:unknown", "alice@example.com"}, Destinations: []string{"tag:prod"}, IP: []string{"tcp:443"}}}
	got := Evaluate(tn, Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:prod"}, Port: "443", Proto: "tcp"})
	if !got.Allowed || got.Indeterminate {
		t.Fatalf("certain selector did not win: %+v", got)
	}
	tn.Grants = []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"*"}, IP: []string{"tcp:443"}}}
	req := Request{SourceLogin: "alice@example.com", DestIPs: []string{"203.0.113.10"}, Port: "443", Proto: "tcp"}
	if Evaluate(tn, req).Allowed {
		t.Fatal("wildcard covered an unadvertised external IP")
	}
	tn.Devices[0].EnabledRoutes = []string{"203.0.113.0/24"}
	if !Evaluate(tn, req).Allowed {
		t.Fatal("wildcard did not cover an approved subnet")
	}
	tn.Grants[0].IP = []string{"future:permission"}
	if got := Evaluate(tn, req); !got.Indeterminate || got.Allowed {
		t.Fatalf("unknown expression was guessed: %+v", got)
	}
	tn.IPSets = map[string][]string{"ipset:a": {"ipset:b"}, "ipset:b": {"ipset:a"}}
	tn.Grants[0].Sources = []string{"ipset:a"}
	tn.Grants[0].IP = []string{"tcp:443"}
	if got := Evaluate(tn, req); !got.Indeterminate {
		t.Fatalf("cyclic set was guessed: %+v", got)
	}
}

func TestWildcardIPCoversEveryProtocol(t *testing.T) {
	for _, entry := range []string{"*", "*:*"} {
		tn := &tailnet.Tailnet{HasAccessRules: true, Grants: []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"*"}, IP: []string{entry}}}}
		for _, proto := range []string{"tcp", "sctp", "gre"} {
			got := Evaluate(tn, Request{SourceLogin: "a@example.com", DestTags: []string{"tag:db"}, Port: "80", Proto: proto})
			if !got.Allowed {
				t.Errorf("ip %q proto %s: %+v", entry, proto, got)
			}
		}
	}
}

func TestIPSetMembersApplyInOrder(t *testing.T) {
	cases := []struct {
		name          string
		members       []string
		allowed, unkn bool
	}{
		{"bare", []string{"100.64.0.0/24"}, true, false},
		{"add", []string{"add 100.64.0.0/24"}, true, false},
		{"removed", []string{"add 100.64.0.0/24", "remove 100.64.0.4"}, false, false},
		{"removed then added", []string{"add 100.64.0.0/24", "remove 100.64.0.4", "add 100.64.0.4"}, true, false},
		{"other host removed", []string{"add 100.64.0.0/24", "remove 100.64.0.9"}, true, false},
		{"range", []string{"add 100.64.0.1-100.64.0.9"}, true, false},
		{"outside range", []string{"add 100.64.0.5-100.64.0.9"}, false, false},
		{"host alias", []string{"add host:db"}, true, false},
		{"missing alias", []string{"add host:nope"}, false, true},
		{"unknown add before certain add", []string{"add autogroup:internet", "add 100.64.0.4"}, true, false},
		{"unknown add leaves no answer", []string{"add autogroup:internet"}, false, true},
		{"unknown removal after add", []string{"add 100.64.0.0/24", "remove host:nope"}, false, true},
		{"unknown removal of absent address", []string{"add 100.64.1.0/24", "remove host:nope"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tn := &tailnet.Tailnet{
				HasAccessRules: true,
				Hosts:          map[string]string{"db": "100.64.0.4"},
				IPSets:         map[string][]string{"ipset:prod": c.members},
				Grants:         []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"ipset:prod"}, IP: []string{"tcp:22"}}},
			}
			got := Evaluate(tn, Request{SourceLogin: "a@example.com", DestIPs: []string{"100.64.0.4"}, Port: "22", Proto: "tcp"})
			if got.Allowed != c.allowed || got.Indeterminate != c.unkn {
				t.Errorf("allowed=%t indeterminate=%t, want %t/%t: %+v", got.Allowed, got.Indeterminate, c.allowed, c.unkn, got.Unsupported)
			}
		})
	}
}

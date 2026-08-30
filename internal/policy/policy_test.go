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
			{Sources: []string{"bob@example.com"}, Destinations: []string{"*:*"}},
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

// Package tailnet defines Taildoc's normalized representation of a tailnet.
// Everything Taildoc knows is derived from the Tailscale API and policy file;
// this model is the single shape all commands operate on.
package tailnet

import (
	"time"
)

// Tailnet is the normalized snapshot of a tailnet at a point in time.
type Tailnet struct {
	Name        string
	CollectedAt time.Time

	Users             []*User
	Devices           []*Device
	Groups            map[string][]string // group name -> members (from policy file)
	TagOwners         map[string][]string // tag name -> owners (from policy file)
	Hosts             map[string]string   // host alias -> IP
	Grants            []*Grant            // normalized from grants + legacy ACLs
	HasAccessRules    bool                // whether acls or grants were explicitly present
	Postures          map[string][]string // posture name -> conditions
	DefaultSrcPosture []string            // policy-wide posture requirements
	AutoApprovers     AutoApprovers
}

// ManagingRoles are the Tailscale roles allowed to administer a tailnet.
var ManagingRoles = []string{"owner", "admin", "network-admin", "it-admin"}

// CanManage reports whether a role is permitted to administer a tailnet.
func CanManage(role string) bool {
	for _, r := range ManagingRoles {
		if r == role {
			return true
		}
	}
	return false
}

// User is a tailnet user.
type User struct {
	ID                 string
	LoginName          string
	DisplayName        string
	Role               string
	Status             string
	Type               string // member, shared, service
	Created            time.Time
	LastSeen           time.Time
	CurrentlyConnected bool
	DeviceCount        int
}

// Device is a node in the tailnet.
type Device struct {
	ID                        string
	NodeID                    string
	Name                      string // full DNS name, e.g. host.tailnet-name.ts.net.
	Hostname                  string
	OS                        string
	ClientVersion             string
	Owner                     string // login name of owning user, empty for tagged devices
	Tags                      []string
	Addresses                 []string // tailscale IPs
	AdvertisedRoutes          []string
	EnabledRoutes             []string
	Online                    bool
	Authorized                bool
	KeyExpiryDisabled         bool
	BlocksIncomingConnections bool
	UpdateAvailable           bool
	IsEphemeral               bool
	IsExternal                bool // shared-in device from another tailnet
	SSHEnabled                bool
	Created                   time.Time
	LastSeen                  time.Time
	Expires                   time.Time
}

// Grant is a normalized allow rule, covering both modern grants and legacy ACLs.
type Grant struct {
	Sources      []string
	Destinations []string
	IP           []string // e.g. "*:*", "5432", "tcp:5432"
	App          map[string][]map[string]any
	SrcPosture   []string
	Via          []string
	Legacy       bool // true if converted from a legacy "acls" entry
}

// AutoApprovers mirrors the policy file's autoApprovers section.
type AutoApprovers struct {
	Routes   map[string][]string
	ExitNode []string
	Services map[string][]string
}

// Sanitize drops nil entries (e.g. from JSON "null" array items in a corrupt
// snapshot) and ensures maps are non-nil so callers can range safely.
func (t *Tailnet) Sanitize() {
	if t == nil {
		return
	}
	users := t.Users[:0]
	for _, u := range t.Users {
		if u == nil || u.LoginName == "" {
			continue
		}
		users = append(users, u)
	}
	t.Users = users
	devs := t.Devices[:0]
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
		devs = append(devs, d)
	}
	t.Devices = devs
	grants := t.Grants[:0]
	for _, g := range t.Grants {
		if g == nil {
			continue
		}
		grants = append(grants, g)
	}
	t.Grants = grants
	if t.Groups == nil {
		t.Groups = map[string][]string{}
	}
	if t.TagOwners == nil {
		t.TagOwners = map[string][]string{}
	}
	if t.Hosts == nil {
		t.Hosts = map[string]string{}
	}
	if t.Postures == nil {
		t.Postures = map[string][]string{}
	}
}

// FindDevice resolves a device by hostname, DNS name, or Tailscale IP.
// Returns nil if no device matches.
func (t *Tailnet) FindDevice(ref string) *Device {
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
		if d.Hostname == ref || d.Name == ref || trimDNS(d.Name) == ref {
			return d
		}
		for _, ip := range d.Addresses {
			if ip == ref {
				return d
			}
		}
	}
	return nil
}

// FindUser resolves a user by login name or display name.
func (t *Tailnet) FindUser(ref string) *User {
	for _, u := range t.Users {
		if u == nil {
			continue
		}
		if u.LoginName == ref || u.DisplayName == ref {
			return u
		}
	}
	return nil
}

// DevicesWithTag returns all devices carrying the given tag (e.g. "tag:prod").
func (t *Tailnet) DevicesWithTag(tag string) []*Device {
	var out []*Device
	for _, d := range t.Devices {
		if d == nil {
			continue
		}
		for _, dt := range d.Tags {
			if dt == tag {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// GroupsOfUser returns the names of groups containing the given login name.
func (t *Tailnet) GroupsOfUser(login string) []string {
	var out []string
	for g, members := range t.Groups {
		for _, m := range members {
			if m == login {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func trimDNS(name string) string {
	// strip ".<tailnet>.ts.net." suffix down to the first label
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return name[:i]
		}
	}
	return name
}

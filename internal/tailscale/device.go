package tailscale

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// Device mirrors the device object returned by
// GET /api/v2/tailnet/{tailnet}/devices?fields=all.
//
// Field names follow Tailscale's published OpenAPI document verbatim. Only the
// fields this tool reasons about are modelled; the rest of the response is
// ignored rather than rejected, so a new server-side field cannot break a run.
type Device struct {
	ID              string   `json:"id"`
	NodeID          string   `json:"nodeId"`
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	User            string   `json:"user"`
	OS              string   `json:"os"`
	ClientVersion   string   `json:"clientVersion"`
	UpdateAvailable bool     `json:"updateAvailable"`
	Addresses       []string `json:"addresses"`
	Tags            []string `json:"tags"`

	Created  APITime `json:"created"`
	LastSeen APITime `json:"lastSeen"`
	Expires  APITime `json:"expires"`

	KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
	Authorized        bool `json:"authorized"`
	IsExternal        bool `json:"isExternal"`
	IsEphemeral       bool `json:"isEphemeral"`
	BlocksIncoming    bool `json:"blocksIncomingConnections"`

	AdvertisedRoutes []string `json:"advertisedRoutes"`
	EnabledRoutes    []string `json:"enabledRoutes"`

	TailnetLockError string `json:"tailnetLockError"`
}

// DisplayName prefers the short hostname over the fully-qualified name, falling
// back through the identifiers so a device is never reported as an empty string.
func (d Device) DisplayName() string {
	switch {
	case d.Hostname != "":
		return d.Hostname
	case d.Name != "":
		return strings.SplitN(d.Name, ".", 2)[0]
	case d.ID != "":
		return d.ID
	default:
		return "(unnamed device)"
	}
}

// Tagged reports whether the device carries any ACL tag, i.e. whether it is a
// tagged server rather than a user-owned machine. Tagged nodes are exempt from
// key renewal, so several rules treat them differently.
func (d Device) Tagged() bool { return len(d.Tags) > 0 }

// UnapprovedRoutes returns the subnet routes this device advertises that an
// admin has not enabled. The API guarantees no ordering, so the result follows
// the advertised list and duplicates are collapsed.
func (d Device) UnapprovedRoutes() []string {
	if len(d.AdvertisedRoutes) == 0 {
		return nil
	}
	enabled := make(map[string]struct{}, len(d.EnabledRoutes))
	for _, r := range d.EnabledRoutes {
		enabled[r] = struct{}{}
	}
	var out []string
	seen := make(map[string]struct{}, len(d.AdvertisedRoutes))
	for _, r := range d.AdvertisedRoutes {
		if _, ok := enabled[r]; ok {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// APITime is an RFC 3339 timestamp that tolerates the representations the API
// actually emits. An absent or empty value decodes to the zero time instead of
// failing the surrounding response: one odd field on one device should not cost
// the caller the other two hundred devices.
type APITime struct {
	time.Time
}

var _ json.Unmarshaler = (*APITime)(nil)

func (t *APITime) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

func (t APITime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`""`), nil
	}
	return json.Marshal(t.Format(time.RFC3339))
}

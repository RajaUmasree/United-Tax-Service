package api

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleOps    Role = "ops"    // UTS staff who work orders
	RoleClient Role = "client" // external customer (title company, lender, ...)
)

type Principal struct {
	Actor    string
	ClientID string
	Role     Role
}

func (p Principal) Staff() bool { return p.Role == RoleAdmin || p.Role == RoleOps }

// CanAccessClient is the single tenant-isolation rule: staff see everything, clients only their own.
func (p Principal) CanAccessClient(clientID string) bool {
	return p.Staff() || (p.ClientID != "" && p.ClientID == clientID)
}

type Authenticator interface {
	Authenticate(token string) (Principal, bool)
}

type tokenEntry struct {
	token []byte
	p     Principal
}

// StaticTokens is a simple bearer-token authenticator for development and service-to-service
// use. Replace with OIDC/JWT validation by implementing Authenticator.
type StaticTokens struct{ entries []tokenEntry }

// ParseTokens parses "token:actor:role[:client_id]" entries separated by commas.
func ParseTokens(spec string) (*StaticTokens, error) {
	st := &StaticTokens{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f := strings.Split(part, ":")
		if len(f) < 3 || len(f) > 4 {
			return nil, fmt.Errorf("invalid token entry %q (want token:actor:role[:client_id])", redactEntry(part))
		}
		p := Principal{Actor: f[1], Role: Role(f[2])}
		if len(f) == 4 {
			p.ClientID = f[3]
		}
		switch p.Role {
		case RoleAdmin, RoleOps:
		case RoleClient:
			if p.ClientID == "" {
				return nil, fmt.Errorf("client token for %q requires a client_id", p.Actor)
			}
		default:
			return nil, fmt.Errorf("unknown role %q for actor %q", p.Role, p.Actor)
		}
		if len(f[0]) < 16 {
			return nil, fmt.Errorf("token for %q is too short (min 16 chars)", p.Actor)
		}
		st.entries = append(st.entries, tokenEntry{token: []byte(f[0]), p: p})
	}
	if len(st.entries) == 0 {
		return nil, fmt.Errorf("no API tokens configured")
	}
	return st, nil
}

func redactEntry(s string) string {
	if i := strings.Index(s, ":"); i > 0 {
		return "[token]" + s[i:]
	}
	return "[entry]"
}

// Authenticate compares against every entry in constant time per comparison and never
// short-circuits, so response timing does not reveal which token prefix matched.
func (s *StaticTokens) Authenticate(token string) (Principal, bool) {
	var found Principal
	ok := 0
	for _, e := range s.entries {
		if subtle.ConstantTimeCompare(e.token, []byte(token)) == 1 {
			found = e.p
			ok = 1
		}
	}
	return found, ok == 1
}

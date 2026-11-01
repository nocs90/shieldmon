package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/nocs90/shieldmon/internal/lifecycle"
)

// Role is what an identity may do (docs/adr/0031-server-mode.md). Each role includes the ones
// below it.
type Role int

const (
	// RoleViewer reads findings, targets, health and reports.
	RoleViewer Role = iota + 1
	// RoleTriager also triages findings and records decisions, as the accountable author.
	RoleTriager
	// RoleAdmin also starts monitoring cycles.
	RoleAdmin
)

var roleNames = map[string]Role{"viewer": RoleViewer, "triager": RoleTriager, "admin": RoleAdmin}

// ParseRole parses viewer, triager or admin.
func ParseRole(s string) (Role, error) {
	if r, ok := roleNames[s]; ok {
		return r, nil
	}
	return 0, fmt.Errorf("role %q: want viewer, triager or admin", s)
}

func (r Role) String() string {
	for n, v := range roleNames {
		if v == r {
			return n
		}
	}
	return "none"
}

// Identity is who sent a request.
type Identity struct {
	Name string
	Role Role
}

// ActorPrefix marks the authors of what the API records: the audit trail tells a token's
// holder from a name typed on the command line, which refuses names with this prefix.
const ActorPrefix = "api:"

// Actor is the author recorded for the identity's transitions and decisions.
func (id Identity) Actor() string { return ActorPrefix + id.Name }

// Authenticator identifies the sender of a request; false when it cannot.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, bool)
}

// tokenPrefix marks ShieldMon API tokens, so that redaction and secret scanners can find them.
const tokenPrefix = "smt_"

// Token is an API token as configured: its holder, role and the SHA-256 of its secret. The
// secret itself is never stored.
type Token struct {
	Name   string
	Role   Role
	SHA256 [32]byte
}

// tokenName bounds the names that become decision authors.
var tokenName = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

// NewToken parses a configured token.
func NewToken(name, role, sum string) (Token, error) {
	if !tokenName.MatchString(name) {
		return Token{}, fmt.Errorf("token name %q: lowercase letters, digits, '.', '_', '@', '-' (at most 64)", name)
	}
	if name == lifecycle.ActorEngine {
		return Token{}, fmt.Errorf("token name %q is reserved for automatic transitions", name)
	}
	r, err := ParseRole(role)
	if err != nil {
		return Token{}, err
	}
	b, err := hex.DecodeString(sum)
	if err != nil || len(b) != sha256.Size {
		return Token{}, fmt.Errorf("token %s: sha256 must be 64 hex digits", name)
	}
	t := Token{Name: name, Role: r}
	copy(t.SHA256[:], b)
	return t, nil
}

// GenerateToken returns a new random secret and the SHA-256 to configure for it.
func GenerateToken() (secret, sum string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(secret))
	return secret, hex.EncodeToString(h[:]), nil
}

// Tokens authenticates "Authorization: Bearer <secret>" against the configured tokens. Every
// token is compared, in constant time, whatever matches first.
type Tokens []Token

func (ts Tokens) Authenticate(r *http.Request) (Identity, bool) {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(secret) > 256 || !strings.HasPrefix(secret, tokenPrefix) {
		return Identity{}, false
	}
	h := sha256.Sum256([]byte(secret))
	var found Identity
	match := 0
	for _, t := range ts {
		if subtle.ConstantTimeCompare(h[:], t.SHA256[:]) == 1 {
			found, match = Identity{Name: t.Name, Role: t.Role}, match+1
		}
	}
	return found, match == 1
}

// Package rp verifies OIDC JWTs locally, including tokens from external providers.
package rp

import (
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alphabravo-oss/identity/pkg/rp/jwks"
	"github.com/golang-jwt/jwt/v5"
)

// Config pins the trust boundary. JWKSURL comes from trusted OIDC discovery.
type Config struct {
	Issuer, Audience, JWKSURL, RolesClaim, Product string
	Algorithms                                     []string
	HTTPClient                                     *http.Client
	MaxTokens                                      int
	// MaxTokenLifetime requires issued-at and bounds expiry minus issued-at when set.
	MaxTokenLifetime time.Duration
	// AuthorizedParty validates azp on multi-audience ID tokens when set.
	AuthorizedParty string
}

// Identity is immutable to callers; Roles returns a copy.
type Identity struct {
	subject            string
	roles              []string
	expires            time.Time
	email, name, nonce string
}

func (i Identity) Subject() string    { return i.subject }
func (i Identity) Expires() time.Time { return i.expires }
func (i Identity) Email() string      { return i.email }
func (i Identity) Name() string       { return i.name }
func (i Identity) Nonce() string      { return i.nonce }
func (i Identity) Roles() []string    { return append([]string(nil), i.roles...) }
func (i Identity) HasRole(role string) bool {
	for _, r := range i.roles {
		if r == role {
			return true
		}
	}
	return false
}

type entry struct {
	key      [32]byte
	identity Identity
}
type Verifier struct {
	config Config
	keys   *jwks.Cache
	parser *jwt.Parser
	mu     sync.Mutex
	memo   map[[32]byte]*list.Element
	lru    *list.List
}

// New preloads keys so normal requests never need discovery or network I/O.
func New(ctx context.Context, c Config) (*Verifier, error) {
	if c.Issuer == "" || c.Audience == "" || c.JWKSURL == "" {
		return nil, errors.New("issuer, audience and JWKS URL are required")
	}
	if c.RolesClaim == "" {
		c.RolesClaim = "alphabravo_roles"
	}
	if len(c.Algorithms) == 0 {
		c.Algorithms = []string{"RS256"}
	}
	for _, a := range c.Algorithms {
		switch jwt.GetSigningMethod(a).(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA, *jwt.SigningMethodEd25519:
		default:
			return nil, errors.New("only asymmetric signing algorithms are supported")
		}
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = 10000
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	keys := jwks.New(c.JWKSURL, c.HTTPClient)
	if err := keys.Refresh(ctx); err != nil {
		return nil, err
	}
	return &Verifier{config: c, keys: keys, parser: jwt.NewParser(jwt.WithValidMethods(c.Algorithms), jwt.WithIssuer(c.Issuer), jwt.WithAudience(c.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt()), memo: make(map[[32]byte]*list.Element), lru: list.New()}, nil
}

func (v *Verifier) Verify(raw string) (Identity, error) {
	if len(raw) > 32768 {
		return Identity{}, errors.New("token too large")
	}
	key := sha256.Sum256([]byte(raw))
	now := time.Now()
	v.mu.Lock()
	if el := v.memo[key]; el != nil {
		i := el.Value.(entry).identity
		if now.Before(i.expires) {
			v.lru.MoveToFront(el)
			v.mu.Unlock()
			return i, nil
		}
		delete(v.memo, key)
		v.lru.Remove(el)
	}
	v.mu.Unlock()
	claims := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(raw, claims, v.keys.Keyfunc); err != nil {
		return Identity{}, err
	}
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return Identity{}, errors.New("missing subject")
	}
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil {
		return Identity{}, errors.New("missing expiry")
	}
	i := Identity{subject: subject, expires: expiry.Time}
	if v.config.MaxTokenLifetime > 0 {
		issued, err := claims.GetIssuedAt()
		if err != nil || issued == nil || !expiry.After(issued.Time) || expiry.Sub(issued.Time) > v.config.MaxTokenLifetime {
			return Identity{}, errors.New("invalid token lifetime")
		}
	}
	if v.config.AuthorizedParty != "" {
		audiences, _ := claims.GetAudience()
		if len(audiences) > 1 && claims["azp"] != v.config.AuthorizedParty {
			return Identity{}, errors.New("invalid authorized party")
		}
	}
	i.email, _ = claims["email"].(string)
	i.name, _ = claims["name"].(string)
	i.nonce, _ = claims["nonce"].(string)
	roles := claims[v.config.RolesClaim]
	if m, ok := roles.(map[string]any); ok {
		roles = m[v.config.Product]
	}
	if a, ok := roles.([]any); ok {
		for _, r := range a {
			if s, ok := r.(string); ok {
				i.roles = append(i.roles, s)
			}
		}
	}
	if role, ok := roles.(string); ok {
		i.roles = []string{role}
	}
	v.mu.Lock()
	if old := v.memo[key]; old != nil {
		v.lru.Remove(old)
	}
	v.memo[key] = v.lru.PushFront(entry{key, i})
	for v.lru.Len() > v.config.MaxTokens {
		el := v.lru.Back()
		delete(v.memo, el.Value.(entry).key)
		v.lru.Remove(el)
	}
	v.mu.Unlock()
	return i, nil
}

// Refresh preloads rotated signing keys; a failed fetch retains last-good keys.
// Call periodically even when every request hits the verification memo.
func (v *Verifier) Refresh(ctx context.Context) error { return v.keys.Refresh(ctx) }

type contextKey struct{}

func FromContext(ctx context.Context) (Identity, bool) {
	i, ok := ctx.Value(contextKey{}).(Identity)
	return i, ok
}
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		i, err := v.Verify(raw)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, i)))
	})
}

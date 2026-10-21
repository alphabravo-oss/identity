package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type fixture struct {
	v        *Verifier
	key      *rsa.PrivateKey
	server   *httptest.Server
	requests atomic.Int64
	fail     atomic.Bool
}

func setup(t testing.TB, claim string) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: key}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if f.fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "one", Use: "sig", Algorithm: "RS256"}}})
	}))
	t.Cleanup(f.server.Close)
	f.v, err = New(context.Background(), Config{Issuer: "https://customer.example", Audience: "wolf", JWKSURL: f.server.URL, Product: "wolf", RolesClaim: claim, MaxTokens: 2})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) token(t testing.TB, change func(jwt.MapClaims)) string {
	t.Helper()
	c := jwt.MapClaims{"iss": "https://customer.example", "aud": "wolf", "sub": "alice", "exp": time.Now().Add(time.Minute).Unix(), "alphabravo_roles": map[string][]string{"wolf": {"viewer"}}}
	if change != nil {
		change(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "one"
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestTrustBoundary(t *testing.T) {
	f := setup(t, "")
	raw := f.token(t, nil)
	i, err := f.v.Verify(raw)
	if err != nil || !i.HasRole("viewer") {
		t.Fatalf("%v %v", i, err)
	}
	roles := i.Roles()
	roles[0] = "admin"
	i, _ = f.v.Verify(raw)
	if i.HasRole("admin") {
		t.Fatal("caller mutated cached roles")
	}
	for _, field := range []string{"iss", "aud", "exp", "sub", "nbf"} {
		t.Run(field, func(t *testing.T) {
			raw := f.token(t, func(c jwt.MapClaims) {
				switch field {
				case "exp":
					c[field] = time.Now().Add(-time.Minute).Unix()
				case "nbf":
					c[field] = time.Now().Add(time.Hour).Unix()
				case "sub":
					delete(c, field)
				default:
					c[field] = "attacker"
				}
			})
			if _, err := f.v.Verify(raw); err == nil {
				t.Fatal("accepted invalid token")
			}
		})
	}
	f.fail.Store(true)
	if err := f.v.keys.Refresh(context.Background()); err == nil {
		t.Fatal("expected rate limit or failure")
	}
	if _, err := f.v.Verify(f.token(t, func(c jwt.MapClaims) { c["jti"] = "new" })); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 1 {
		t.Fatal("request path performed network calls")
	}
}
func TestExternalRolesAndBoundedCache(t *testing.T) {
	f := setup(t, "groups")
	for n := 0; n < 5; n++ {
		raw := f.token(t, func(c jwt.MapClaims) { c["jti"] = n; c["groups"] = []string{"operator"} })
		i, err := f.v.Verify(raw)
		if err != nil || !i.HasRole("operator") {
			t.Fatalf("%v %v", i, err)
		}
	}
	if len(f.v.memo) != 2 {
		t.Fatal("memo is not bounded")
	}
}
func TestMemoExpiry(t *testing.T) {
	f := setup(t, "")
	raw := f.token(t, nil)
	_, _ = f.v.Verify(raw)
	key := f.v.lru.Front().Value.(entry).key
	el := f.v.memo[key]
	e := el.Value.(entry)
	e.identity.expires = time.Now().Add(-time.Second)
	el.Value = e
	f.v.parser = jwt.NewParser(jwt.WithIssuer("wrong"))
	if _, err := f.v.Verify(raw); err == nil {
		t.Fatal("expired memo was reused")
	}
}
func BenchmarkVerify(b *testing.B) {
	f := setup(b, "")
	raw := f.token(b, nil)
	if _, err := f.v.Verify(raw); err != nil {
		b.Fatal(err)
	}
	before := f.requests.Load()
	b.Run("memoized", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := f.v.Verify(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("first-sighting", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f.v.mu.Lock()
			clear(f.v.memo)
			f.v.lru.Init()
			f.v.mu.Unlock()
			if _, err := f.v.Verify(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
	if f.requests.Load() != before {
		b.Fatal("network in benchmark")
	}
}

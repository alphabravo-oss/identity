package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alphabravo-oss/identity/internal/registry"
)

var cookieCipher cipher.AEAD

func initCipher() {
	key, err := os.ReadFile(env("COOKIE_KEY_FILE", "/runtime/cookie-key"))
	if err != nil || len(key) != 32 {
		log.Fatal("32-byte cookie encryption key required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	cookieCipher, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func seal(name, value string) string {
	nonce := make([]byte, cookieCipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	b, _ := json.Marshal(struct {
		Value string
		Exp   int64
	}{value, time.Now().Add(12 * time.Hour).Unix()})
	return base64.RawURLEncoding.EncodeToString(cookieCipher.Seal(nonce, nonce, b, []byte(name)))
}
func getCookie(r *http.Request, name string) (*http.Cookie, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(b) < cookieCipher.NonceSize() {
		return nil, errors.New("invalid cookie")
	}
	n := cookieCipher.NonceSize()
	raw, err := cookieCipher.Open(nil, b[:n], b[n:], []byte(name))
	if err != nil {
		return nil, err
	}
	var v struct {
		Value string
		Exp   int64
	}
	if json.Unmarshal(raw, &v) != nil || v.Exp < time.Now().Unix() {
		return nil, errors.New("expired cookie")
	}
	c.Value = v.Value
	return c, nil
}

var configMu sync.RWMutex
var registryHash [32]byte

func loadConfig() {
	path := os.Getenv("REGISTRY_FILE")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- Operator-owned mounted registry path.
	if err != nil {
		log.Fatal("product registry unavailable")
	}
	if err = applyConfig(raw); err != nil {
		log.Fatal("invalid product registry")
	}

}

func applyConfig(raw []byte) error {
	hash := sha256.Sum256(raw)
	if hash == registryHash {
		return nil
	}
	var c registry.Runtime
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	configMu.Lock()
	defer configMu.Unlock()
	brands, groupMap, idps = c.Brands, c.GroupMap, c.IDPs
	if err := os.Setenv("ORG_ID", c.OrgID); err != nil {
		return err
	}
	registryHash = hash
	return nil
}
func watchConfig(ctx context.Context) {
	path := os.Getenv("REGISTRY_FILE")
	if path == "" {
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			b, err := os.ReadFile(path) // #nosec G304 G703 -- Operator-owned mounted registry; retain last good config on read/parse failure.
			if err == nil {
				_ = applyConfig(b)
			}
		}
	}
}

type bucket struct {
	start time.Time
	n     int
}

var limits = struct {
	sync.Mutex
	entries map[string]bucket
}{entries: map[string]bucket{}}

func protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configMu.RLock()
		defer configMu.RUnlock()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			origin := r.Header.Get("Origin")
			public, _ := url.Parse(base)
			if origin != "" && origin != "null" && origin != public.Scheme+"://"+public.Host {
				http.Error(w, "Invalid request origin", http.StatusForbidden)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid form", 400)
				return
			}
			c, err := getCookie(r, "ab_csrf")
			csrf := r.FormValue("csrf")
			if err != nil || csrf == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(csrf)) != 1 {
				http.Error(w, "Expired form. Reload and try again.", http.StatusForbidden)
				return
			}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			limits.Lock()
			now := time.Now()
			b := limits.entries[host]
			if now.Sub(b.start) > time.Minute {
				b = bucket{start: now}
			}
			b.n++
			if len(limits.entries) > 10000 {
				for k, v := range limits.entries {
					if now.Sub(v.start) > time.Minute {
						delete(limits.entries, k)
					}
				}
			}
			if len(limits.entries) < 10000 {
				limits.entries[host] = b
			}
			limited := b.n > 30
			limits.Unlock()
			if limited {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too many attempts. Try again shortly.", http.StatusTooManyRequests)
				return
			}
		}
		// Hide file-server listings and source files; static resources are an explicit allowlist.
		if strings.HasPrefix(r.URL.Path, "/signin/static/") {
			switch r.URL.Path {
			case "/signin/static/inter.woff2", "/signin/static/tokens.css", "/signin/static/autopost.js", "/signin/static/passkey.js":
			default:
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

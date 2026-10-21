// demo-product is a minimal product integration: OIDC code + PKCE and pkg/rp.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alphabravo-oss/identity/pkg/rp"
	"golang.org/x/oauth2"
)

func env(k, def string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return def
}
func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func main() {
	issuer := env("ISSUER", "https://identity.example.com")
	id := os.Getenv("CLIENT_ID")
	secret := os.Getenv("CLIENT_SECRET")
	slug := env("PRODUCT", "demo-product")
	callback := env("CALLBACK", "https://demo.identity.test/callback")
	cfg := oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: callback, Scopes: []string{"openid", "profile", "email"}, Endpoint: oauth2.Endpoint{AuthURL: issuer + "/oauth/v2/authorize", TokenURL: issuer + "/oauth/v2/token", AuthStyle: oauth2.AuthStyleInHeader}}
	var verifier *rp.Verifier
	var err error
	for n := 0; n < 60; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		verifier, err = rp.New(ctx, rp.Config{Issuer: issuer, Audience: id, JWKSURL: env("JWKS_URL", issuer+"/oauth/v2/keys"), Product: slug, RolesClaim: env("ROLES_CLAIM", "alphabravo_roles")})
		cancel()
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		state, pkce := random(), oauth2.GenerateVerifier()
		cookie(w, "ab_flow", state+"."+pkce, 300)
		http.Redirect(w, r, cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(pkce)), http.StatusFound)
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("ab_flow")
		if err != nil {
			http.Error(w, "Expired sign-in", 400)
			return
		}
		state, pkce, ok := strings.Cut(c.Value, ".")
		if !ok || state != r.URL.Query().Get("state") {
			http.Error(w, "Invalid state", 400)
			return
		}
		cookie(w, "ab_flow", "", -1)
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			log.Print(err)
			http.Error(w, "Sign-in failed", http.StatusBadGateway)
			return
		}
		if _, err = verifier.Verify(token.AccessToken); err != nil {
			log.Print(err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		cookie(w, "ab_token", token.AccessToken, 600)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("ab_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		i, err := verifier.Verify(c.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"product": slug, "subject": i.Subject(), "roles": i.Roles()})
	})
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

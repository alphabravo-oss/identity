// demo-product delegates authentication entirely to pkg/rp's browser integration.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alphabravo-oss/identity/pkg/rp"
)

func env(k, def string) string {
	if value := os.Getenv(k); value != "" {
		return value
	}
	return def
}
func main() {
	issuer := env("ISSUER", "https://identity.example.com")
	slug := env("PRODUCT", "demo-product")
	var web *rp.Web
	var err error
	for n := 0; n < 60; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		web, err = rp.NewWeb(ctx, rp.WebConfig{Config: rp.Config{Issuer: issuer, Audience: os.Getenv("CLIENT_ID"), JWKSURL: env("JWKS_URL", issuer+"/oauth/v2/keys"), Product: slug, RolesClaim: env("ROLES_CLAIM", "alphabravo_roles")}, ClientSecret: os.Getenv("CLIENT_SECRET"), RedirectURI: env("CALLBACK", "https://demo.identity.test/callback"), AuthorizationURL: os.Getenv("AUTHORIZATION_URL"), TokenURL: os.Getenv("TOKEN_URL"), CookieName: "ab_token"})
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /login", web.Login)
	mux.HandleFunc("GET /callback", web.Callback)
	mux.HandleFunc("POST /logout", web.Logout)
	mux.Handle("GET /{$}", web.Session(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := rp.FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"product": slug, "subject": identity.Subject(), "roles": identity.Roles()})
	})))
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

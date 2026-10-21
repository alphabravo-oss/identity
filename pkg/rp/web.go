package rp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// WebConfig adds the browser code flow to local JWT verification. For bypass mode,
// AuthorizationURL and TokenURL come from the external provider's trusted discovery.
type WebConfig struct {
	Config
	ClientSecret, RedirectURI, AuthorizationURL, TokenURL string
	CookieName, LoginPath, SuccessPath                    string
}

// Web owns PKCE, browser-bound state, token exchange and secure session cookies.
// Products register its handlers and authorize the Identity from request context.
type Web struct {
	verifier               *Verifier
	oauth                  oauth2.Config
	client                 *http.Client
	cookie, login, success string
}

func NewWeb(ctx context.Context, c WebConfig) (*Web, error) {
	callback, err := url.Parse(c.RedirectURI)
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.Fragment != "" {
		return nil, errors.New("HTTPS callback URI required")
	}
	if c.LoginPath == "" {
		c.LoginPath = "/login"
	}
	if c.SuccessPath == "" {
		c.SuccessPath = "/"
	}
	for _, path := range []string{c.LoginPath, c.SuccessPath} {
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			return nil, errors.New("local login and success paths required")
		}
	}
	if c.CookieName == "" {
		c.CookieName = "__Host-ab.rp"
	}
	if c.AuthorizationURL == "" {
		c.AuthorizationURL = c.Issuer + "/oauth/v2/authorize"
	}
	if c.TokenURL == "" {
		c.TokenURL = c.Issuer + "/oauth/v2/token"
	}
	for _, endpoint := range []string{c.AuthorizationURL, c.TokenURL} {
		u, e := url.Parse(endpoint)
		if e != nil || u.Host == "" || u.Scheme != "https" {
			return nil, errors.New("HTTPS OIDC endpoints required")
		}
	}
	verifier, err := New(ctx, c.Config)
	if err != nil {
		return nil, err
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Web{verifier: verifier, client: hc, cookie: c.CookieName, login: c.LoginPath, success: c.SuccessPath, oauth: oauth2.Config{ClientID: c.Audience, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURI, Scopes: []string{"openid", "profile", "email"}, Endpoint: oauth2.Endpoint{AuthURL: c.AuthorizationURL, TokenURL: c.TokenURL, AuthStyle: oauth2.AuthStyleInHeader}}}, nil
}
func (w *Web) setCookie(out http.ResponseWriter, name, value string, age int) {
	http.SetCookie(out, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func (w *Web) Login(out http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(out, "Sign-in unavailable", http.StatusServiceUnavailable)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	pkce := oauth2.GenerateVerifier()
	w.setCookie(out, w.cookie+".flow", state+"."+pkce, 300)
	out.Header().Set("Cache-Control", "no-store")
	http.Redirect(out, r, w.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(pkce)), http.StatusFound)
}
func (w *Web) Callback(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("Referrer-Policy", "no-referrer")
	flow, err := r.Cookie(w.cookie + ".flow")
	if err != nil {
		http.Error(out, "Expired sign-in", http.StatusBadRequest)
		return
	}
	state, pkce, ok := strings.Cut(flow.Value, ".")
	if !ok || state == "" || state != r.URL.Query().Get("state") {
		http.Error(out, "Invalid state", http.StatusBadRequest)
		return
	}
	w.setCookie(out, w.cookie+".flow", "", -1)
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, w.client), 10*time.Second)
	defer cancel()
	token, err := w.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkce))
	if err != nil {
		http.Error(out, "Sign-in failed", http.StatusBadGateway)
		return
	}
	identity, err := w.verifier.Verify(token.AccessToken)
	if err != nil {
		http.Error(out, "Invalid token", http.StatusUnauthorized)
		return
	}
	if len(token.AccessToken) > 3800 {
		http.Error(out, "Token exceeds browser session budget", http.StatusBadGateway)
		return
	}
	w.setCookie(out, w.cookie, token.AccessToken, int(time.Until(identity.expires).Seconds()))
	http.Redirect(out, r, w.success, http.StatusSeeOther)
}

// Session protects browser GET handlers. Products must apply their normal CSRF
// protection to state-changing cookie-authenticated routes.
func (w *Web) Session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(w.cookie)
		if err == nil {
			if identity, e := w.verifier.Verify(c.Value); e == nil {
				next.ServeHTTP(out, r.WithContext(context.WithValue(r.Context(), contextKey{}, identity)))
				return
			}
		}
		http.Redirect(out, r, w.login, http.StatusFound)
	})
}

// Logout clears the product session. End the shared identity session separately
// through the issuer's registered OIDC end-session flow when desired.
func (w *Web) Logout(out http.ResponseWriter, r *http.Request) {
	w.setCookie(out, w.cookie, "", -1)
	http.Redirect(out, r, w.login, http.StatusSeeOther)
}

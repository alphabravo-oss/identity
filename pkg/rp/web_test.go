package rp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWebStateAndPKCE(t *testing.T) {
	f := setup(t, "")
	web, err := NewWeb(context.Background(), WebConfig{Config: Config{Issuer: "https://customer.example", Audience: "wolf", JWKSURL: f.server.URL}, ClientSecret: "secret", RedirectURI: "https://wolf.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	web.Login(w, httptest.NewRequest("GET", "https://wolf.example/login", nil))
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" || u.Query().Get("state") == "" {
		t.Fatal("missing PKCE/state")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe flow cookie")
	}
	r := httptest.NewRequest("GET", "https://wolf.example/callback?code=attacker&state=wrong", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	before := f.requests.Load()
	web.Callback(w, r)
	if w.Code != http.StatusBadRequest || f.requests.Load() != before {
		t.Fatal("bad state reached token exchange")
	}
}
func TestWebRejectsExternalSuccessRedirect(t *testing.T) {
	_, err := NewWeb(context.Background(), WebConfig{RedirectURI: "https://wolf.example/callback", SuccessPath: "//attacker.example"})
	if err == nil {
		t.Fatal("accepted open redirect")
	}
}

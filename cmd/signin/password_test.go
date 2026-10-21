package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCombinedPasswordTOTP(t *testing.T) {
	testCipher(t)
	oldAPI, oldHost := api, apiHost
	t.Cleanup(func() { api, apiHost = oldAPI, oldHost })
	calls := 0
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/zitadel.session.v2.SessionService/CreateSession":
			var body struct {
				Checks struct {
					Password struct{ Password string }
					TOTP     struct{ Code string }
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Checks.Password.Password != "password" || body.Checks.TOTP.Code != "123456" {
				t.Error("both factors must reach the engine")
			}
			_, _ = w.Write([]byte(`{"sessionId":"session","sessionToken":"opaque"}`))
		case "/zitadel.oidc.v2.OIDCService/CreateCallback":
			_, _ = w.Write([]byte(`{"callbackUrl":"https://wolf.example/callback"}`))
		default:
			t.Errorf("unexpected extra RPC: %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer engine.Close()
	api, apiHost = engine.URL, ""
	form := url.Values{"authRequest": {"request"}, "username": {"bob"}, "password": {"password"}, "code": {"123456"}}
	r := httptest.NewRequest("POST", "/signin/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	password(w, r)
	if w.Code != http.StatusFound || calls != 2 {
		t.Fatalf("status=%d RPCs=%d", w.Code, calls)
	}
}

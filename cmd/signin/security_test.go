package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testCipher(t *testing.T) {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookieCipher, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCookieAuthentication(t *testing.T) {
	testCipher(t)
	value := seal("ab_session", "secret")
	r := httptest.NewRequest("GET", "/signin/login", nil)
	r.AddCookie(&http.Cookie{Name: "ab_session", Value: value})
	c, err := getCookie(r, "ab_session")
	if err != nil || c.Value != "secret" {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "ab_pending", Value: value})
	if _, err := getCookie(r, "ab_pending"); err == nil {
		t.Fatal("cookie transferable between purposes")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "ab_session", Value: value[:len(value)-8] + "tampered"})
	if _, err := getCookie(r, "ab_session"); err == nil {
		t.Fatal("tampered cookie accepted")
	}
}
func TestCSRFAndStaticAllowlist(t *testing.T) {
	testCipher(t)
	h := protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, path := range []string{"/signin/password", "/signin/totp", "/signin/reset/finish"} {
		r := httptest.NewRequest("POST", path, strings.NewReader("username=x"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/signin/static/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestGroupExtraction(t *testing.T) {
	got := groups([]byte(`{"rawInformation":{"groups":["operators"],"memberOf":["cn=admins,ou=groups,dc=corp"]}}`))
	if !sameSet(got, []string{"admins", "operators"}) {
		t.Fatal(got)
	}
}

func TestNullOriginStillRequiresCSRF(t *testing.T) {
	testCipher(t)
	h := protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest("POST", "/signin/password", strings.NewReader("csrf=bound-token"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "null")
	r.AddCookie(&http.Cookie{Name: "ab_csrf", Value: seal("ab_csrf", "bound-token")})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
}

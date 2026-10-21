// Command login-kit is a prototype of our own sign-in page on top of Zitadel's Session API v2.
// Zitadel stays invisible: it only redirects the browser here (per-app Login V2 base URI) and we
// finish the OIDC auth request through the API. Stateless: the only state is two HttpOnly cookies
// holding opaque Zitadel session ids/tokens, so it scales horizontally.
//
// Flows: username+password (+TOTP when enrolled), LDAP form, redirect IdPs (OIDC, SAML), silent SSO
// from an existing session, logout. External-IdP groups are synced to project roles on every sign-in.
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/alphabravo-oss/identity/internal/claims"
	"github.com/alphabravo-oss/identity/internal/registry"
)

//go:embed static page.html emails
var assets embed.FS

var (
	api      = env("ENGINE_API", "https://identity.example.com") // in-cluster: http://zitadel.<ns>.svc:8080 (API is not public)
	apiHost  = os.Getenv("ENGINE_HOST")                          // instance is selected by Host: the external domain
	base     = env("PUBLIC_BASE", "https://identity.example.com/signin")
	pat      = strings.TrimSpace(readFile(env("LOGIN_PAT_FILE", "/secrets/login-client.pat")))
	idps     = mustJSON[map[string]string](env("IDPS", "{}"))        // kind -> idp id ("ldap", "oidc", "saml")
	brands   = mustJSON[map[string]Brand](env("BRANDS", "{}"))       // OIDC client id -> brand
	groupMap = mustJSON[map[string][]string](env("GROUP_MAP", "{}")) // external group -> ["<projectId>:<role>"]
	page     = template.Must(template.ParseFS(assets, "page.html"))
	hc       = &http.Client{Timeout: 10 * time.Second}
)

type Brand = registry.Branding

type view struct {
	Brand                               Brand
	Step, AuthRequest, Err              string
	CSRF, Options, Secret, UserID, Code string
	IDPs                                map[string]string
	Theme                               string
	PostURL                             string
	PostFields                          map[string]string
}

func main() {
	loadConfig()
	initCipher()
	mux := http.NewServeMux()
	mux.Handle("GET /signin/static/", http.StripPrefix("/signin", http.FileServerFS(assets)))
	mux.HandleFunc("GET /signin/login", loginPage)
	mux.HandleFunc("POST /signin/password", password)
	mux.HandleFunc("POST /signin/passkey/start", passkeyStart)
	mux.HandleFunc("GET /signin/security", securityPage)
	mux.HandleFunc("POST /signin/passkey/register", passkeyRegister)
	mux.HandleFunc("POST /signin/passkey/register/finish", passkeyRegisterFinish)
	mux.HandleFunc("POST /signin/passkey/finish", passkeyFinish)
	mux.HandleFunc("GET /signin/reset", resetPage)
	mux.HandleFunc("GET /signin/invite", invitePage)
	mux.HandleFunc("POST /signin/invite", inviteAccept)
	mux.HandleFunc("POST /signin/reset", resetRequest)
	mux.HandleFunc("POST /signin/reset/finish", resetFinish)
	mux.HandleFunc("POST /signin/enroll", enrollTOTP)
	mux.HandleFunc("POST /signin/totp", totp)
	mux.HandleFunc("POST /signin/ldap", ldap)
	mux.HandleFunc("GET /signin/idp/{kind}", startRedirectIDP)
	mux.HandleFunc("GET /signin/idp/done", idpDone)
	mux.HandleFunc("GET /signin/logout", logout)
	mux.HandleFunc("GET /logout/done", logout) // Zitadel's fallback after end_session without post_logout_redirect_uri
	mux.HandleFunc("GET /signin/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	srv := &http.Server{Addr: ":8080", Handler: protect(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	internalMux := http.NewServeMux()
	internalMux.Handle("POST /claims", claims.Handler([]byte(strings.TrimSpace(readFile(env("CLAIMS_KEY_FILE", "/runtime/claims-key"))))))
	internalMux.HandleFunc("POST /invitations", invite)
	internal := &http.Server{Addr: ":8090", Handler: internalMux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		if err := internal.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go watchConfig(ctx)
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(deadline)
		_ = internal.Shutdown(deadline)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// --- handlers ---------------------------------------------------------------------------------

func loginPage(w http.ResponseWriter, r *http.Request) {
	ar := r.URL.Query().Get("authRequest")
	var req struct {
		AuthRequest struct {
			ClientID string   `json:"clientId"`
			Prompt   []string `json:"prompt"`
		} `json:"authRequest"`
	}
	if err := rpc("zitadel.oidc.v2.OIDCService/GetAuthRequest", map[string]string{"authRequestId": ar}, &req); err != nil {
		render(w, r, view{Step: "error", Err: "This sign-in link has expired. Return to the application and try again."})
		return
	}
	setCookie(w, "ab_client", req.AuthRequest.ClientID, 0)
	// Silent SSO: reuse the browser's session unless the app forces a fresh login.
	if c, err := getCookie(r, "ab_session"); err == nil && !slices.Contains(req.AuthRequest.Prompt, "PROMPT_LOGIN") {
		if id, tok, ok := strings.Cut(c.Value, "."); ok && finalize(w, r, ar, id, tok) == nil {
			return
		}
	}
	render(w, r, view{Step: "login", AuthRequest: ar, Brand: brands[req.AuthRequest.ClientID]})
}

func password(w http.ResponseWriter, r *http.Request) {
	ar := r.FormValue("authRequest")
	checks := map[string]any{
		"user":     map[string]string{"loginName": r.FormValue("username")},
		"password": map[string]string{"password": r.FormValue("password")},
	}
	code := r.FormValue("code")
	if code != "" {
		checks["totp"] = map[string]string{"code": code}
	}
	s, err := createSession(checks)
	if err != nil {
		render(w, r, view{Step: "login", AuthRequest: ar, Err: "The password or verification code did not work."})
		return
	}
	// A successful combined check has verified both factors in the engine.
	// Empty codes retain the enrollment and separate second-factor flow below.
	if code != "" {
		done(w, r, ar, s)
		return
	}
	var m struct{ AuthMethodTypes []string }
	if err := rpc("zitadel.user.v2.UserService/ListAuthenticationMethodTypes", map[string]string{"userId": s.userID()}, &m); err != nil {
		fail(w, r, err)
		return
	}
	if slices.Contains(m.AuthMethodTypes, "AUTHENTICATION_METHOD_TYPE_TOTP") {
		setCookie(w, "ab_pending", s.ID+"."+s.Token, 300)
		render(w, r, view{Step: "totp", AuthRequest: ar})
		return
	}
	if env("REQUIRE_TOTP", "true") == "true" {
		setCookie(w, "ab_pending", s.ID+"."+s.Token, 300)
		var res struct{ Secret, URI string }
		if err := rpc("zitadel.user.v2.UserService/RegisterTOTP", map[string]string{"userId": s.userID()}, &res); err != nil {
			fail(w, r, err)
			return
		}
		render(w, r, view{Step: "enroll", AuthRequest: ar, Secret: res.Secret})
		return
	}
	done(w, r, ar, s)
}

func totp(w http.ResponseWriter, r *http.Request) {
	ar := r.FormValue("authRequest")
	c, err := getCookie(r, "ab_pending")
	id, tok, _ := strings.Cut(cookieValue(c, err), ".")
	var res struct{ SessionToken string }
	if err := rpc("zitadel.session.v2.SessionService/SetSession", map[string]any{
		"sessionId": id, "sessionToken": tok, "checks": map[string]any{"totp": map[string]string{"code": r.FormValue("code")}},
	}, &res); err != nil {
		render(w, r, view{Step: "totp", AuthRequest: ar, Err: "That code didn't work. Try the current code from your authenticator app."})
		return
	}
	setCookie(w, "ab_pending", "", -1)
	done(w, r, ar, &session{ID: id, Token: res.SessionToken})
}

func ldap(w http.ResponseWriter, r *http.Request) {
	ar := r.FormValue("authRequest")
	var res struct{ IdpIntent intent }
	if err := rpc("zitadel.user.v2.UserService/StartIdentityProviderIntent", map[string]any{
		"idpId": idps["ldap"], "ldap": map[string]string{"username": r.FormValue("username"), "password": r.FormValue("password")},
	}, &res); err != nil {
		render(w, r, view{Step: "login", AuthRequest: ar, Err: "Your directory rejected that username or password."})
		return
	}
	federated(w, r, ar, res.IdpIntent)
}

func startRedirectIDP(w http.ResponseWriter, r *http.Request) {
	ar := r.URL.Query().Get("authRequest")
	state := randomToken()
	setCookie(w, "ab_federation", ar+"."+state, 300)
	back := base + "/idp/done?authRequest=" + url.QueryEscape(ar) + "&state=" + url.QueryEscape(state)
	var res struct {
		AuthURL  string `json:"authUrl"`
		FormData *struct {
			URL    string            `json:"url"`
			Fields map[string]string `json:"fields"`
		} `json:"formData"`
	}
	if err := rpc("zitadel.user.v2.UserService/StartIdentityProviderIntent", map[string]any{
		"idpId": idps[r.PathValue("kind")], "urls": map[string]string{"successUrl": back, "failureUrl": back},
	}, &res); err != nil {
		fail(w, r, err)
		return
	}
	if res.FormData != nil { // SAML POST binding: we render the auto-submitting form ourselves
		render(w, r, view{Step: "post", PostURL: res.FormData.URL, PostFields: res.FormData.Fields})
		return
	}
	http.Redirect(w, r, res.AuthURL, http.StatusFound)
}

func idpDone(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := getCookie(r, "ab_federation")
	if err != nil || c.Value != q.Get("authRequest")+"."+q.Get("state") {
		fail(w, r, errors.New("invalid federation state"))
		return
	}
	setCookie(w, "ab_federation", "", -1)
	if q.Get("id") == "" {
		render(w, r, view{Step: "login", AuthRequest: q.Get("authRequest"), Err: "Sign-in with your organization was cancelled or failed."})
		return
	}
	federated(w, r, q.Get("authRequest"), intent{ID: q.Get("id"), Token: q.Get("token")})
}

// federated finishes any external-IdP sign-in: JIT-create or find the user, sync roles, open a session.
func federated(w http.ResponseWriter, r *http.Request, ar string, in intent) {
	var res struct {
		UserID         string          `json:"userId"`
		IdpInformation json.RawMessage `json:"idpInformation"`
		AddHumanUser   map[string]any  `json:"addHumanUser"`
	}
	if err := rpc("zitadel.user.v2.UserService/RetrieveIdentityProviderIntent",
		map[string]string{"idpIntentId": in.ID, "idpIntentToken": in.Token}, &res); err != nil {
		fail(w, r, err)
		return
	}
	userID := res.UserID
	if userID == "" { // JIT provisioning from the IdP's suggested profile, linked to the external identity
		u := res.AddHumanUser
		if u == nil {
			fail(w, r, errors.New("missing federated profile"))
			return
		}
		u["organization"] = map[string]string{"orgId": org()}
		fillFromSAML(u, res.IdpInformation)
		var created struct{ UserID string }
		if err := rpc("zitadel.user.v2.UserService/AddHumanUser", u, &created); err != nil {
			fail(w, r, err)
			return
		}
		userID = created.UserID
	}
	if err := syncRoles(userID, groups(res.IdpInformation)); err != nil {
		fail(w, r, err)
		return
	}
	s, err := createSession(map[string]any{
		"user":      map[string]string{"userId": userID},
		"idpIntent": map[string]string{"idpIntentId": in.ID, "idpIntentToken": in.Token},
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	done(w, r, ar, s)
}

// fillFromSAML completes Zitadel's suggested profile for SAML IdPs, whose attributes it does not map.
func fillFromSAML(u map[string]any, info json.RawMessage) {
	var in struct {
		RawInformation struct{ Attributes map[string][]string } `json:"rawInformation"`
	}
	if json.Unmarshal(info, &in) != nil || in.RawInformation.Attributes == nil {
		return
	}
	a := func(k string) string {
		if v := in.RawInformation.Attributes[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	prof, _ := u["profile"].(map[string]any)
	if prof == nil {
		prof = map[string]any{}
		u["profile"] = prof
	}
	for k, attr := range map[string]string{"givenName": "firstName", "familyName": "lastName"} {
		if s, _ := prof[k].(string); s == "" {
			prof[k] = a(attr)
		}
	}
	if s, _ := u["username"].(string); s == "" {
		u["username"] = a("username")
	}
	links, _ := u["idpLinks"].([]any)
	for _, l := range links {
		if m, ok := l.(map[string]any); ok && m["userName"] == nil {
			m["userName"] = a("username")
		}
	}
	if e, _ := u["email"].(map[string]any); e == nil || e["email"] == "" || e["email"] == nil {
		u["email"] = map[string]any{"email": a("email"), "isVerified": true}
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	if c, err := getCookie(r, "ab_session"); err == nil {
		if id, tok, ok := strings.Cut(c.Value, "."); ok {
			_ = rpc("zitadel.session.v2.SessionService/DeleteSession", map[string]string{"sessionId": id, "sessionToken": tok}, &struct{}{})
		}
	}
	setCookie(w, "ab_session", "", -1)

	render(w, r, view{Step: "signedout"})
}

// --- session + OIDC helpers -------------------------------------------------------------------

type session struct {
	ID    string `json:"sessionId"`
	Token string `json:"sessionToken"`
	uid   string
}

type intent struct {
	ID    string `json:"idpIntentId"`
	Token string `json:"idpIntentToken"`
}

func createSession(checks map[string]any) (*session, error) {
	var s session
	err := rpc("zitadel.session.v2.SessionService/CreateSession", map[string]any{"checks": checks, "lifetime": "43200s"}, &s)
	return &s, err
}

func (s *session) userID() string {
	if s.uid == "" {
		var res struct {
			Session struct {
				Factors struct{ User struct{ ID string } }
			}
		}
		_ = rpc("zitadel.session.v2.SessionService/GetSession", map[string]string{"sessionId": s.ID, "sessionToken": s.Token}, &res)
		s.uid = res.Session.Factors.User.ID
	}
	return s.uid
}

func done(w http.ResponseWriter, r *http.Request, ar string, s *session) {
	if err := finalize(w, r, ar, s.ID, s.Token); err != nil {
		fail(w, r, err)
	}
}

func finalize(w http.ResponseWriter, r *http.Request, ar, id, tok string) error {
	var cb struct{ CallbackURL string }
	if err := rpc("zitadel.oidc.v2.OIDCService/CreateCallback", map[string]any{
		"authRequestId": ar, "session": map[string]string{"sessionId": id, "sessionToken": tok},
	}, &cb); err != nil {
		return err
	}
	setCookie(w, "ab_session", id+"."+tok, 12*3600)
	http.Redirect(w, r, cb.CallbackURL, http.StatusFound)
	return nil
}

// --- group → role sync --------------------------------------------------------------------------

// groups extracts group names from any IdP's raw information: OIDC "groups" claim, SAML "groups"
// attribute, LDAP "memberOf" DNs (reduced to their CN).
func groups(raw json.RawMessage) []string {
	var out []string
	var walk func(k string, v any)
	walk = func(k string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for kk, vv := range t {
				walk(kk, vv)
			}
		case []any:
			for _, vv := range t {
				walk(k, vv)
			}
		case string:
			switch strings.ToLower(k) {
			case "groups":
				out = append(out, t)
			case "memberof", "profile":
				if cn, ok := strings.CutPrefix(strings.Split(t, ",")[0], "cn="); ok {
					out = append(out, cn)
				}
			}
		}
	}
	var v any
	_ = json.Unmarshal(raw, &v)
	walk("", v)
	slices.Sort(out)
	return slices.Compact(out) // LDAP memberOf arrives twice: raw attributes and the profile mapping
}

// syncRoles makes the user's grants on every mapped project equal to what their groups imply,
// so removing someone from a group upstream removes the role on their next sign-in.
func syncRoles(userID string, gs []string) error {
	want := map[string][]string{} // project -> roles
	for _, ps := range groupMap {
		for _, p := range ps {
			proj, _, _ := strings.Cut(p, ":")
			want[proj] = nil
		}
	}
	for _, g := range gs {
		for _, p := range groupMap[g] {
			proj, role, _ := strings.Cut(p, ":")
			want[proj] = append(want[proj], role)
		}
	}
	var list struct {
		Authorizations []struct {
			ID      string
			Project struct{ ID string }
			Roles   []struct{ Key string }
		}
	}
	if err := rpc("zitadel.authorization.v2.AuthorizationService/ListAuthorizations", map[string]any{
		"filters": []any{map[string]any{"inUserIds": map[string]any{"ids": []string{userID}}}},
	}, &list); err != nil {
		return err
	}
	have := map[string]string{} // project -> authorization id
	for _, a := range list.Authorizations {
		roles := []string{}
		for _, r := range a.Roles {
			roles = append(roles, r.Key)
		}
		have[a.Project.ID] = a.ID
		w, managed := want[a.Project.ID]
		// Emptying the role list (instead of deleting) needs only user.grant.write, which the login client has.
		if managed && !sameSet(w, roles) {
			if w == nil {
				w = []string{}
			}
			if err := rpc("zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", map[string]any{"id": a.ID, "roleKeys": w}, &struct{}{}); err != nil {
				return err
			}
		}
	}
	for proj, roles := range want {
		if _, ok := have[proj]; !ok && len(roles) > 0 {
			if err := rpc("zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
				"userId": userID, "projectId": proj, "organizationId": org(), "roleKeys": roles,
			}, &struct{}{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// --- plumbing ---------------------------------------------------------------------------------

func rpc(method string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, api+"/"+method, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+pat)
	if apiHost != "" {
		req.Host = apiHost
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d %s", method, res.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

func render(w http.ResponseWriter, r *http.Request, v view) {
	if c, err := getCookie(r, "ab_client"); err == nil && v.Brand.Product == "" {
		v.Brand = brands[c.Value]
	}
	if v.Brand.Product == "" {
		v.Brand = Brand{Product: "AlphaBravo", Accent: "#4f46e5", AccentDark: "#818cf8"}
	}
	v.IDPs, v.Theme = idps, r.URL.Query().Get("theme")
	if v.Theme != "light" && v.Theme != "dark" {
		v.Theme = ""
	}
	if c, err := getCookie(r, "ab_csrf"); err == nil {
		v.CSRF = c.Value
	} else {
		v.CSRF = randomToken()
		setCookie(w, "ab_csrf", v.CSRF, 3600)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self' https:; img-src 'self' https:")
	if err := page.Execute(w, v); err != nil {
		log.Print(err)
	}
}

// fail logs the Zitadel error and shows a neutral message; raw upstream errors never reach the user.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("sign-in error: %v", err)
	w.WriteHeader(http.StatusBadGateway)
	render(w, r, view{Step: "error", Err: "Something went wrong while signing you in. Please try again."})
}

func setCookie(w http.ResponseWriter, name, v string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: seal(name, v), Path: "/signin", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func cookieValue(c *http.Cookie, err error) string {
	if err != nil {
		return ""
	}
	return c.Value
}

func org() string { return os.Getenv("ORG_ID") }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func readFile(p string) string {
	b, err := os.ReadFile(p) // #nosec G304 G703 -- Deployment-controlled paths; no request data enters file paths.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	return string(b)
}

func mustJSON[T any](s string) T {
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		log.Fatalf("bad JSON config %q: %v", s, err)
	}
	return v
}

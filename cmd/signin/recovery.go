package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
)

func resetPage(w http.ResponseWriter, r *http.Request) {
	v := view{Step: "reset"}
	if r.URL.Query().Get("code") != "" {
		v.Step = "reset-finish"
		v.UserID = r.URL.Query().Get("userId")
		v.Code = r.URL.Query().Get("code")
	}
	render(w, r, v)
}
func resetRequest(w http.ResponseWriter, r *http.Request) {
	var users struct {
		Result []struct {
			UserID string
			Human  struct{ Email struct{ Email string } }
		}
	}
	err := rpc("zitadel.user.v2.UserService/ListUsers", map[string]any{"queries": []any{map[string]any{"loginNameQuery": map[string]string{"loginName": r.FormValue("username"), "method": "TEXT_QUERY_METHOD_EQUALS"}}}}, &users)
	if err == nil && len(users.Result) == 1 {
		u := users.Result[0]
		var code struct{ VerificationCode string }
		if err = rpc("zitadel.user.v2.UserService/PasswordReset", map[string]any{"userId": u.UserID, "returnCode": map[string]any{}}, &code); err == nil {
			link := base + "/reset?" + url.Values{"userId": {u.UserID}, "code": {code.VerificationCode}}.Encode()
			err = sendMail(u.Human.Email.Email, "Reset your password", "Use this link to reset your password:\r\n\r\n"+link+"\r\n\r\nIf you did not request this, ignore this email.")
		}
		if err != nil {
			log.Print("recovery delivery failed")
		}
	}
	render(w, r, view{Step: "reset-sent"})
}
func sendMail(to, subject, body string) error {
	from := env("SMTP_FROM", "AlphaBravo <identity@example.com>")
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return err
	}
	recipient, err := mail.ParseAddress(to)
	if err != nil {
		return err
	}
	if strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("invalid subject")
	}
	addr := env("SMTP_ADDRESS", "")
	if addr == "" {
		return fmt.Errorf("SMTP not configured")
	}
	msg := []byte("From: " + sender.String() + "\r\nTo: " + recipient.String() + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n\r\nAlphaBravo Identity\r\n")
	// Private/offline SMTP relays can run without authentication; Go negotiates STARTTLS when offered.
	return smtp.SendMail(addr, nil, sender.Address, []string{recipient.Address}, msg)
}
func resetFinish(w http.ResponseWriter, r *http.Request) {
	v := view{Step: "reset-finish", UserID: r.FormValue("userId"), Code: r.FormValue("code")}
	password := r.FormValue("password")
	if len(password) < 12 {
		v.Err = "Use at least 12 characters."
		render(w, r, v)
		return
	}
	err := rpc("zitadel.user.v2.UserService/SetPassword", map[string]any{"userId": v.UserID, "verificationCode": v.Code, "newPassword": map[string]any{"password": password, "changeRequired": false}}, &struct{}{})
	if err != nil {
		v.Err = "This link has expired or the password does not meet your policy."
		render(w, r, v)
		return
	}
	render(w, r, view{Step: "reset-done"})
}
func enrollTOTP(w http.ResponseWriter, r *http.Request) {
	c, err := getCookie(r, "ab_pending")
	id, tok, ok := strings.Cut(cookieValue(c, err), ".")
	if !ok {
		fail(w, r, fmt.Errorf("missing enrollment session"))
		return
	}
	s := &session{ID: id, Token: tok}
	uid := s.userID()
	if err := rpc("zitadel.user.v2.UserService/VerifyTOTPRegistration", map[string]string{"userId": uid, "code": r.FormValue("code")}, &struct{}{}); err != nil {
		fail(w, r, err)
		return
	}
	totp(w, r)
}
func passkeyStart(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(base)
	var out struct {
		SessionID, SessionToken string
		Challenges              struct {
			WebAuthN struct{ PublicKeyCredentialRequestOptions json.RawMessage }
		}
	}
	err := rpc("zitadel.session.v2.SessionService/CreateSession", map[string]any{"checks": map[string]any{"user": map[string]string{"loginName": r.FormValue("username")}}, "challenges": map[string]any{"webAuthN": map[string]string{"domain": u.Hostname(), "userVerificationRequirement": "USER_VERIFICATION_REQUIREMENT_REQUIRED"}}, "lifetime": "300s"}, &out)
	if err != nil {
		fail(w, r, err)
		return
	}
	setCookie(w, "ab_pending", out.SessionID+"."+out.SessionToken, 300)
	render(w, r, view{Step: "passkey", AuthRequest: r.FormValue("authRequest"), Options: string(out.Challenges.WebAuthN.PublicKeyCredentialRequestOptions)})
}
func passkeyFinish(w http.ResponseWriter, r *http.Request) {
	c, err := getCookie(r, "ab_pending")
	id, tok, ok := strings.Cut(cookieValue(c, err), ".")
	if !ok {
		fail(w, r, fmt.Errorf("missing passkey session"))
		return
	}
	var credential map[string]any
	if json.Unmarshal([]byte(r.FormValue("assertion")), &credential) != nil {
		fail(w, r, fmt.Errorf("bad assertion"))
		return
	}
	var out struct{ SessionToken string }
	err = rpc("zitadel.session.v2.SessionService/SetSession", map[string]any{"sessionId": id, "sessionToken": tok, "checks": map[string]any{"webAuthN": map[string]any{"credentialAssertionData": credential}}, "lifetime": "43200s"}, &out)
	if err != nil {
		fail(w, r, err)
		return
	}
	setCookie(w, "ab_pending", "", -1)
	done(w, r, r.FormValue("authRequest"), &session{ID: id, Token: out.SessionToken})
}

func invitePage(w http.ResponseWriter, r *http.Request) {
	render(w, r, view{Step: "invite", UserID: r.URL.Query().Get("userId"), Code: r.URL.Query().Get("code")})
}
func inviteAccept(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("userId")
	if err := rpc("zitadel.user.v2.UserService/VerifyInviteCode", map[string]string{"userId": uid, "verificationCode": r.FormValue("code")}, &struct{}{}); err != nil {
		fail(w, r, err)
		return
	}
	var out struct{ VerificationCode string }
	if err := rpc("zitadel.user.v2.UserService/PasswordReset", map[string]any{"userId": uid, "returnCode": map[string]any{}}, &out); err != nil {
		fail(w, r, err)
		return
	}
	render(w, r, view{Step: "reset-finish", UserID: uid, Code: out.VerificationCode})
}

// currentUser requires a completed shared login; a pending password-only session is insufficient.
func currentUser(r *http.Request) (string, error) {
	c, err := getCookie(r, "ab_session")
	id, tok, ok := strings.Cut(cookieValue(c, err), ".")
	if !ok {
		return "", fmt.Errorf("sign in before managing credentials")
	}
	var out struct {
		Session struct {
			Factors struct {
				User                     struct{ ID string }
				Password, WebAuthN, TOTP json.RawMessage
			}
		}
	}
	if err := rpc("zitadel.session.v2.SessionService/GetSession", map[string]string{"sessionId": id, "sessionToken": tok}, &out); err != nil {
		return "", err
	}
	f := out.Session.Factors
	if f.User.ID == "" || (len(f.Password) == 0 && len(f.WebAuthN) == 0) {
		return "", fmt.Errorf("local authentication required")
	}
	return f.User.ID, nil
}
func securityPage(w http.ResponseWriter, r *http.Request) {
	if _, err := currentUser(r); err != nil {
		fail(w, r, err)
		return
	}
	render(w, r, view{Step: "security"})
}
func passkeyRegister(w http.ResponseWriter, r *http.Request) {
	uid, err := currentUser(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	u, _ := url.Parse(base)
	var out struct {
		PasskeyID                          string
		PublicKeyCredentialCreationOptions map[string]any
	}
	if err := rpc("zitadel.user.v2.UserService/RegisterPasskey", map[string]string{"userId": uid, "domain": u.Hostname()}, &out); err != nil {
		fail(w, r, err)
		return
	}
	options := out.PublicKeyCredentialCreationOptions
	pub, _ := options["publicKey"].(map[string]any)
	if pub == nil {
		pub = options
	}
	if rp, ok := pub["rp"].(map[string]any); ok {
		rp["name"] = "AlphaBravo"
	}
	b, _ := json.Marshal(options)
	setCookie(w, "ab_registration", uid+"."+out.PasskeyID, 300)
	render(w, r, view{Step: "passkey-register", Options: string(b)})
}
func passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	uid, err := currentUser(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	c, err := getCookie(r, "ab_registration")
	user, id, ok := strings.Cut(cookieValue(c, err), ".")
	if !ok || user != uid {
		fail(w, r, fmt.Errorf("expired passkey registration"))
		return
	}
	var credential map[string]any
	if json.Unmarshal([]byte(r.FormValue("assertion")), &credential) != nil {
		fail(w, r, fmt.Errorf("invalid credential"))
		return
	}
	if err := rpc("zitadel.user.v2.UserService/VerifyPasskeyRegistration", map[string]any{"userId": uid, "passkeyId": id, "publicKeyCredential": credential, "passkeyName": "Passkey"}, &struct{}{}); err != nil {
		fail(w, r, err)
		return
	}
	setCookie(w, "ab_registration", "", -1)
	render(w, r, view{Step: "passkey-created"})
}

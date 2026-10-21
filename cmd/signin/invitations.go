package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	texttemplate "text/template"
)

var mailTemplates = texttemplate.Must(texttemplate.ParseFS(assets, "emails/*.txt"))

func mailBody(name, product, link string) (string, error) {
	var out bytes.Buffer
	err := mailTemplates.ExecuteTemplate(&out, name+".txt", struct{ Product, Link string }{product, link})
	return out.String(), err
}

// invite is private on port 8090 and requires an operator-distributed capability.
// The credential is never exposed through ingress or product client credentials.
func invite(w http.ResponseWriter, r *http.Request) {
	key, err := os.ReadFile("/runtime/mail-token")
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err != nil || len(key) == 0 || subtle.ConstantTimeCompare(key, []byte(supplied)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct{ ClientID, Username, Email, GivenName, FamilyName string }
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		http.Error(w, "Invalid invitation", http.StatusBadRequest)
		return
	}
	configMu.RLock()
	brand, ok := brands[input.ClientID]
	organization := org()
	configMu.RUnlock()
	if !ok {
		http.Error(w, "Unknown product", http.StatusBadRequest)
		return
	}
	var user struct{ ID string }
	if err := rpc("zitadel.user.v2.UserService/CreateUser", map[string]any{"organizationId": organization, "username": input.Username, "human": map[string]any{"profile": map[string]string{"givenName": input.GivenName, "familyName": input.FamilyName}, "email": map[string]any{"email": input.Email, "returnCode": map[string]any{}}}}, &user); err != nil {
		http.Error(w, "Unable to create invitation", http.StatusBadGateway)
		return
	}
	var code struct{ InviteCode string }
	if err := rpc("zitadel.user.v2.UserService/CreateInviteCode", map[string]any{"userId": user.ID, "returnCode": map[string]any{}}, &code); err != nil {
		http.Error(w, "Unable to create invitation", http.StatusBadGateway)
		return
	}
	link := base + "/invite?" + url.Values{"userId": {user.ID}, "code": {code.InviteCode}}.Encode()
	body, err := mailBody("invitation", brand.Product, link)
	if err == nil {
		err = sendMail(input.Email, "You're invited to "+brand.Product, body)
	}
	if err != nil {
		http.Error(w, "Invitation created; delivery failed. Resend through the administration API.", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"userId": user.ID})
}

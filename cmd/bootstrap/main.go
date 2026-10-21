// Command bootstrap converges the registry, credentials, login configuration and claims Action.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alphabravo-oss/identity/internal/kube"
	"github.com/alphabravo-oss/identity/internal/registry"
	"github.com/alphabravo-oss/identity/pkg/provision"
)

type store struct {
	kube   *kube.Client
	prefix string
}

func (s store) Put(ctx context.Context, slug string, r provision.Result) error {
	return s.kube.Put(ctx, s.prefix+slug, map[string][]byte{"client-id": []byte(r.ClientID), "client-secret": []byte(r.ClientSecret), "project-id": []byte(r.ProjectID), "issuer": []byte(os.Getenv("PUBLIC_ISSUER"))})
}

var api, host, pat string

func rpc(ctx context.Context, method string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", api+"/"+method, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	b, err = io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %d %s", method, res.StatusCode, b)
	}
	return json.Unmarshal(b, out)
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}
func run(ctx context.Context) error {
	api, host = os.Getenv("ENGINE_API"), os.Getenv("ENGINE_HOST")
	b, err := os.ReadFile(os.Getenv("ADMIN_PAT_FILE")) // #nosec G703 -- Operator-controlled credential mount path, never request input.
	if err != nil {
		return err
	}
	pat = strings.TrimSpace(string(b))
	kc, err := kube.InCluster()
	if err != nil {
		return err
	}
	var products []registry.Product
	b, err = os.ReadFile("/config/products.json")
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &products); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range products {
		if err = p.Validate(); err != nil {
			return err
		}
		if seen[p.Slug] {
			return fmt.Errorf("duplicate slug %s", p.Slug)
		}
		seen[p.Slug] = true
	}
	// Wait for setup projections and new-pod NetworkPolicies.
	for {
		err = rpc(ctx, "zitadel.org.v2.OrganizationService/ListOrganizations", map[string]any{}, &struct{}{})
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Second):
		}
	}
	c, err := provision.ConnectToken(ctx, host, os.Getenv("ENGINE_ADDRESS"), pat, store{kc, os.Getenv("SECRET_PREFIX")})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	runtime := registry.Runtime{Brands: map[string]registry.Branding{}, GroupMap: map[string][]string{}, IDPs: map[string]string{}}
	for _, p := range products {
		result, err := c.Ensure(ctx, provision.Spec{Org: os.Getenv("ORGANIZATION"), Project: p.Slug, App: p.Slug, Roles: p.Roles, RedirectURIs: p.RedirectURIs, PostLogoutRedirects: p.PostLogoutRedirects, LoginBaseURI: os.Getenv("PUBLIC_ISSUER") + "/signin"})
		if err != nil {
			return err
		}
		// A missing create-only credential is a hard failure; never silently rotate a client's secret.
		if !result.Created {
			if _, err = kc.Get(ctx, os.Getenv("SECRET_PREFIX")+p.Slug); err != nil {
				return fmt.Errorf("%s credentials missing: restore the Secret from backup", p.Slug)
			}
		}
		p.Branding.Product = p.DisplayName
		runtime.Brands[result.ClientID] = p.Branding
		runtime.OrgID = result.OrgID
		for group, roles := range p.GroupRoles {
			for _, role := range roles {
				runtime.GroupMap[group] = append(runtime.GroupMap[group], result.ProjectID+":"+role)
			}
		}
		log.Printf("registered %s created=%v updated=%v", p.Slug, result.Created, result.Updated)
	}
	// An installation may start without products; discover its organization explicitly.
	if runtime.OrgID == "" {
		var orgs struct{ Result []struct{ ID, Name string } }
		if err = rpc(ctx, "zitadel.org.v2.OrganizationService/ListOrganizations", map[string]any{}, &orgs); err != nil {
			return err
		}
		for _, o := range orgs.Result {
			if o.Name == os.Getenv("ORGANIZATION") {
				runtime.OrgID = o.ID
			}
		}
	}
	if runtime.OrgID == "" {
		return fmt.Errorf("organization missing")
	}
	name := os.Getenv("RUNTIME_SECRET")
	existing, _ := kc.Get(ctx, name)
	data := existing.Data
	if data == nil {
		data = map[string][]byte{}
	}
	if len(data["cookie-key"]) != 32 {
		data["cookie-key"] = make([]byte, 32)
		if _, err = rand.Read(data["cookie-key"]); err != nil {
			return err
		}
	}
	// Persist the target signing key immediately: it is only returned on create.
	if len(data["mail-token"]) == 0 {
		b := make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		data["mail-token"] = []byte(hex.EncodeToString(b))
	}
	if len(data["saml-branding-key"]) == 0 {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		data["saml-branding-key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	target := string(data["target-id"])
	if target == "" {
		var res struct{ ID, SigningKey string }
		if err = rpc(ctx, "zitadel.action.v2.ActionService/CreateTarget", map[string]any{"name": os.Getenv("ACTION_NAME"), "restCall": map[string]bool{"interruptOnError": true}, "timeout": "5s", "endpoint": os.Getenv("CLAIMS_ENDPOINT")}, &res); err != nil {
			return err
		}
		target = res.ID
		data["claims-key"] = []byte(res.SigningKey)
		data["target-id"] = []byte(target)
		if err = kc.Put(ctx, name, data); err != nil {
			return err
		}
	}
	for _, function := range []string{"preaccesstoken", "preuserinfo"} {
		if err = rpc(ctx, "zitadel.action.v2.ActionService/SetExecution", map[string]any{"condition": map[string]any{"function": map[string]string{"name": function}}, "targets": []string{target}}, &struct{}{}); err != nil {
			return err
		}
	}
	if err = rpc(ctx, "zitadel.feature.v2.FeatureService/SetInstanceFeatures", map[string]any{"loginV2": map[string]any{"required": true, "baseUri": os.Getenv("PUBLIC_ISSUER") + "/signin"}}, &struct{}{}); err != nil {
		return err
	}
	// Retain explicitly configured external providers on registry upgrades.
	if b := data["registry.json"]; len(b) > 0 {
		var old registry.Runtime
		if json.Unmarshal(b, &old) == nil {
			runtime.IDPs = old.IDPs
		}
	}
	if path := os.Getenv("PROVIDERS_FILE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- Operator-selected Secret mount, not request data.
		if err != nil {
			return err
		}
		var providers struct {
			OIDC *provision.OIDCSettings `json:"oidc"`
			SAML *provision.SAMLSettings `json:"saml"`
			LDAP *provision.LDAPSettings `json:"ldap"`
		}
		if err = json.Unmarshal(b, &providers); err != nil {
			return err
		}
		if providers.OIDC != nil {
			runtime.IDPs["oidc"], err = c.ConfigureOIDCProvider(ctx, os.Getenv("ORGANIZATION"), *providers.OIDC)
			if err != nil {
				return err
			}
		}
		if providers.SAML != nil {
			runtime.IDPs["saml"], err = c.ConfigureSAMLProvider(ctx, os.Getenv("ORGANIZATION"), *providers.SAML)
			if err != nil {
				return err
			}
		}
		if providers.LDAP != nil {
			runtime.IDPs["ldap"], err = c.ConfigureLDAPProvider(ctx, os.Getenv("ORGANIZATION"), *providers.LDAP)
			if err != nil {
				return err
			}
		}
	}
	b, err = json.Marshal(runtime)
	if err != nil {
		return err
	}
	data["registry.json"] = b
	// The sign-in credential is supplied separately; bootstrap never hands its admin token to signin.
	if len(data["login-client.pat"]) == 0 {
		uid := string(data["login-user-id"])
		if uid == "" {
			var u struct{ ID string }
			if err = rpc(ctx, "zitadel.user.v2.UserService/CreateUser", map[string]any{"organizationId": runtime.OrgID, "username": os.Getenv("ACTION_NAME") + "-login", "machine": map[string]string{"name": "AlphaBravo sign-in"}}, &u); err != nil {
				return err
			}
			uid = u.ID
			data["login-user-id"] = []byte(uid)
			if err = kc.Put(ctx, name, data); err != nil {
				return err
			}
		}
		err = rpc(ctx, "admin/v1/members", map[string]any{"userId": uid, "roles": []string{"IAM_LOGIN_CLIENT"}}, &struct{}{})
		if err != nil && !strings.Contains(err.Error(), "already_exists") {
			return err
		}
		var token struct{ Token string }
		if err = rpc(ctx, "zitadel.user.v2.UserService/AddPersonalAccessToken", map[string]string{"userId": uid, "expirationDate": time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)}, &token); err != nil {
			return err
		}
		data["login-client.pat"] = []byte(token.Token)
	}

	return kc.Put(ctx, name, data)
}

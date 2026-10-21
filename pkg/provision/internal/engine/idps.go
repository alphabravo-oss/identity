package engine

// Capability-shaped wrappers behind a product's "Identity providers" settings page. Each call
// creates or updates one org-scoped provider by display name and returns its ID. Zitadel v4.19 has
// no v2 API for provider management, so these use management v1 (the only v1 surface we touch).

import (
	"context"
	"fmt"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/idp"
	mgmt "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"google.golang.org/protobuf/types/known/durationpb"
)

// JIT: users are created on first sign-in and their profile refreshed on every sign-in.
var jit = &idp.Options{IsLinkingAllowed: true, IsCreationAllowed: true, IsAutoCreation: true, IsAutoUpdate: true}

type LDAPSettings struct {
	Name, BindDN, BindPassword, BaseDN, UserBase string
	Servers                                      []string // ldap://host:389 or ldaps://host:636
	StartTLS                                     bool
	RootCA                                       []byte
	LoginAttribute                               string // "uid" (OpenLDAP) or "sAMAccountName" (AD)
	ObjectClass                                  string // "inetOrgPerson" or "user"
	GroupAttribute                               string // "memberOf"; handed to the login handler for group→role sync
}

type OIDCSettings struct {
	Name, Issuer, ClientID, ClientSecret string
	Scopes                               []string // must include the scope that releases the groups claim
}

type SAMLSettings struct {
	Name, MetadataURL string
}

func ConfigureLDAPProvider(ctx context.Context, c *client.Client, org string, s LDAPSettings) (string, error) {
	attrs := &idp.LDAPAttributes{
		IdAttribute: "entryUUID", PreferredUsernameAttribute: s.LoginAttribute,
		FirstNameAttribute: "givenName", LastNameAttribute: "sn", DisplayNameAttribute: "cn", EmailAttribute: "mail",
		// Zitadel fetches only mapped attributes and has no group mapping. memberOf is operational
		// (returned only when requested), so it rides in the otherwise unused profile mapping.
		ProfileAttribute: s.GroupAttribute,
	}
	timeout := durationpb.New(10 * time.Second)
	return upsert(ctx, c, org, s.Name,
		func(ctx context.Context, m mgmt.ManagementServiceClient) (string, error) {
			r, err := m.AddLDAPProvider(ctx, &mgmt.AddLDAPProviderRequest{Name: s.Name, Servers: s.Servers, StartTls: s.StartTLS,
				BaseDn: s.BaseDN, BindDn: s.BindDN, BindPassword: s.BindPassword, UserBase: s.UserBase,
				UserObjectClasses: []string{s.ObjectClass}, UserFilters: []string{s.LoginAttribute}, Timeout: timeout,
				Attributes: attrs, ProviderOptions: jit, RootCa: s.RootCA})
			return r.GetId(), err
		},
		func(ctx context.Context, m mgmt.ManagementServiceClient, id string) error {
			_, err := m.UpdateLDAPProvider(ctx, &mgmt.UpdateLDAPProviderRequest{Id: id, Name: s.Name, Servers: s.Servers, StartTls: s.StartTLS,
				BaseDn: s.BaseDN, BindDn: s.BindDN, BindPassword: s.BindPassword, UserBase: s.UserBase,
				UserObjectClasses: []string{s.ObjectClass}, UserFilters: []string{s.LoginAttribute}, Timeout: timeout,
				Attributes: attrs, ProviderOptions: jit, RootCa: s.RootCA})
			return err
		})
}

func ConfigureOIDCProvider(ctx context.Context, c *client.Client, org string, s OIDCSettings) (string, error) {
	return upsert(ctx, c, org, s.Name,
		func(ctx context.Context, m mgmt.ManagementServiceClient) (string, error) {
			r, err := m.AddGenericOIDCProvider(ctx, &mgmt.AddGenericOIDCProviderRequest{Name: s.Name, Issuer: s.Issuer,
				ClientId: s.ClientID, ClientSecret: s.ClientSecret, Scopes: s.Scopes, ProviderOptions: jit,
				IsIdTokenMapping: true, UsePkce: true})
			return r.GetId(), err
		},
		func(ctx context.Context, m mgmt.ManagementServiceClient, id string) error {
			_, err := m.UpdateGenericOIDCProvider(ctx, &mgmt.UpdateGenericOIDCProviderRequest{Id: id, Name: s.Name, Issuer: s.Issuer,
				ClientId: s.ClientID, ClientSecret: s.ClientSecret, Scopes: s.Scopes, ProviderOptions: jit,
				IsIdTokenMapping: true, UsePkce: true})
			return err
		})
}

func ConfigureSAMLProvider(ctx context.Context, c *client.Client, org string, s SAMLSettings) (string, error) {
	persistent := idp.SAMLNameIDFormat_SAML_NAME_ID_FORMAT_PERSISTENT
	return upsert(ctx, c, org, s.Name,
		func(ctx context.Context, m mgmt.ManagementServiceClient) (string, error) {
			r, err := m.AddSAMLProvider(ctx, &mgmt.AddSAMLProviderRequest{Name: s.Name,
				Metadata: &mgmt.AddSAMLProviderRequest_MetadataUrl{MetadataUrl: s.MetadataURL},
				Binding:  idp.SAMLBinding_SAML_BINDING_POST, WithSignedRequest: true, SignatureAlgorithm: idp.SAMLSignatureAlgorithm_SAML_SIGNATURE_RSA_SHA256, NameIdFormat: &persistent, ProviderOptions: jit})
			return r.GetId(), err
		},
		func(ctx context.Context, m mgmt.ManagementServiceClient, id string) error {
			_, err := m.UpdateSAMLProvider(ctx, &mgmt.UpdateSAMLProviderRequest{Id: id, Name: s.Name,
				Metadata: &mgmt.UpdateSAMLProviderRequest_MetadataUrl{MetadataUrl: s.MetadataURL},
				Binding:  idp.SAMLBinding_SAML_BINDING_POST, WithSignedRequest: true, SignatureAlgorithm: idp.SAMLSignatureAlgorithm_SAML_SIGNATURE_RSA_SHA256, NameIdFormat: &persistent, ProviderOptions: jit})
			return err
		})
}

// upsert finds the org's provider by name and updates it, or adds it.
func upsert(ctx context.Context, c *client.Client, org, name string,
	add func(context.Context, mgmt.ManagementServiceClient) (string, error), update func(context.Context, mgmt.ManagementServiceClient, string) error) (string, error) {
	id, err := orgID(ctx, c, org)
	if err != nil {
		return "", err
	}
	ctx = middleware.SetOrgID(ctx, id)
	m := c.ManagementService()
	list, err := m.ListProviders(ctx, &mgmt.ListProvidersRequest{Queries: []*mgmt.ProviderQuery{
		{Query: &mgmt.ProviderQuery_IdpNameQuery{IdpNameQuery: &idp.IDPNameQuery{Name: name}}},
	}})
	if err != nil {
		return "", fmt.Errorf("list providers: %w", err)
	}
	for _, p := range list.Result {
		if p.Name == name && p.Owner == idp.IDPOwnerType_IDP_OWNER_TYPE_ORG {
			return p.Id, update(ctx, m, p.Id)
		}
	}
	return add(ctx, m)
}

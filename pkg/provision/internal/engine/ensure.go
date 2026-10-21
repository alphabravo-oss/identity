// Package zprov idempotently provisions OIDC clients in Zitadel through the v2 API.
// It is the code path a catalog installer uses to SSO-wire a tool before it starts.
package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	app "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	org "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	project "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Spec names the desired OIDC web client. Org must exist; project, roles and app are created on demand.
type Spec struct {
	Org, Project, App   string
	Roles               []string
	RedirectURIs        []string
	PostLogoutRedirects []string
	LoginBaseURI        string // our own sign-in page for this app (custom login on the Session API)
}

// Result is what the installer injects into the release. ClientSecret is set only when the
// app was created (Zitadel never returns it again); persist it in a Secret on first run.
type Result struct {
	OrgID, ProjectID, AppID, ClientID, ClientSecret string
	Created, Updated                                bool
}

// Ensure converges Zitadel to spec. Re-running with the same spec performs reads only.
func Ensure(ctx context.Context, c *client.Client, s Spec) (Result, error) {
	var r Result
	var err error
	if r.OrgID, err = orgID(ctx, c, s.Org); err != nil {
		return r, err
	}
	if r.ProjectID, err = ensureProject(ctx, c, r.OrgID, s.Project); err != nil {
		return r, err
	}
	for _, role := range s.Roles {
		_, err := c.ProjectServiceV2().AddProjectRole(ctx, &project.AddProjectRoleRequest{ProjectId: r.ProjectID, RoleKey: role, DisplayName: role})
		if err != nil && status.Code(err) != codes.AlreadyExists {
			return r, fmt.Errorf("role %s: %w", role, err)
		}
	}
	return r, ensureApp(ctx, c, s, &r)
}

func orgID(ctx context.Context, c *client.Client, name string) (string, error) {
	res, err := c.OrganizationServiceV2().ListOrganizations(ctx, &org.ListOrganizationsRequest{
		Queries: []*org.SearchQuery{{Query: &org.SearchQuery_NameQuery{NameQuery: &org.OrganizationNameQuery{Name: name}}}},
	})
	if err != nil {
		return "", fmt.Errorf("list orgs: %w", err)
	}
	if len(res.Result) != 1 {
		return "", fmt.Errorf("org %q: found %d", name, len(res.Result))
	}
	return res.Result[0].Id, nil
}

func ensureProject(ctx context.Context, c *client.Client, orgID, name string) (string, error) {
	res, err := c.ProjectServiceV2().ListProjects(ctx, &project.ListProjectsRequest{Filters: []*project.ProjectSearchFilter{
		{Filter: &project.ProjectSearchFilter_ProjectNameFilter{ProjectNameFilter: &project.ProjectNameFilter{ProjectName: name}}},
		{Filter: &project.ProjectSearchFilter_OrganizationIdFilter{OrganizationIdFilter: &project.ProjectOrganizationIDFilter{OrganizationId: orgID}}},
	}})
	if err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range res.Projects {
		if p.Name == name && p.OrganizationId == orgID {
			return p.ProjectId, nil
		}
	}
	cr, err := c.ProjectServiceV2().CreateProject(ctx, &project.CreateProjectRequest{OrganizationId: orgID, Name: name, ProjectRoleAssertion: true})
	if err != nil {
		return "", fmt.Errorf("create project: %w", err)
	}
	return cr.ProjectId, nil
}

func ensureApp(ctx context.Context, c *client.Client, s Spec, r *Result) error {
	res, err := c.ApplicationServiceV2().ListApplications(ctx, &app.ListApplicationsRequest{Filters: []*app.ApplicationSearchFilter{
		{Filter: &app.ApplicationSearchFilter_ProjectIdFilter{ProjectIdFilter: &app.ProjectIDFilter{ProjectId: r.ProjectID}}},
		{Filter: &app.ApplicationSearchFilter_NameFilter{NameFilter: &app.ApplicationNameFilter{Name: s.App}}},
	}})
	if err != nil {
		return fmt.Errorf("list apps: %w", err)
	}
	for _, a := range res.Applications {
		oc := a.GetOidcConfiguration()
		if a.Name != s.App || oc == nil {
			continue
		}
		r.AppID, r.ClientID = a.ApplicationId, oc.ClientId
		if slices.Equal(oc.RedirectUris, s.RedirectURIs) && slices.Equal(oc.PostLogoutRedirectUris, s.PostLogoutRedirects) &&
			oc.GetLoginVersion().GetLoginV2().GetBaseUri() == s.LoginBaseURI && oc.GetIdTokenUserinfoAssertion() {
			return nil
		}
		_, err := c.ApplicationServiceV2().UpdateApplication(ctx, &app.UpdateApplicationRequest{
			ApplicationId: a.ApplicationId, ProjectId: r.ProjectID,
			ApplicationType: &app.UpdateApplicationRequest_OidcConfiguration{OidcConfiguration: &app.UpdateOIDCApplicationConfigurationRequest{
				RedirectUris: s.RedirectURIs, PostLogoutRedirectUris: s.PostLogoutRedirects, LoginVersion: loginVersion(s.LoginBaseURI), IdTokenUserinfoAssertion: ptr(true),
			}},
		})
		r.Updated = err == nil
		return err
	}
	cr, err := c.ApplicationServiceV2().CreateApplication(ctx, &app.CreateApplicationRequest{
		ProjectId: r.ProjectID, Name: s.App,
		ApplicationType: &app.CreateApplicationRequest_OidcConfiguration{OidcConfiguration: &app.CreateOIDCApplicationRequest{
			RedirectUris:           s.RedirectURIs,
			PostLogoutRedirectUris: s.PostLogoutRedirects,
			ResponseTypes:          []app.OIDCResponseType{app.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
			GrantTypes:             []app.OIDCGrantType{app.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE, app.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN},
			ApplicationType:        app.OIDCApplicationType_OIDC_APP_TYPE_WEB,
			AuthMethodType:         app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
			AccessTokenType:        app.OIDCTokenType_OIDC_TOKEN_TYPE_JWT, // RPs validate locally against JWKS
			// Roles reach the token only via the alphabravo_roles Action (project role assertion stays on,
			// which is what feeds user_grants to the Action); this keeps urn:zitadel:* claims out of tokens.
			AccessTokenRoleAssertion: false,
			IdTokenRoleAssertion:     false,
			IdTokenUserinfoAssertion: true,
			LoginVersion:             loginVersion(s.LoginBaseURI),
		}},
	})
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	oc := cr.GetOidcConfiguration()
	r.AppID, r.ClientID, r.ClientSecret, r.Created = cr.ApplicationId, oc.ClientId, oc.ClientSecret, true
	return nil
}

func loginVersion(baseURI string) *app.LoginVersion {
	if baseURI == "" {
		return nil // instance default
	}
	return &app.LoginVersion{Version: &app.LoginVersion_LoginV2{LoginV2: &app.LoginV2{BaseUri: &baseURI}}}
}

func ptr[T any](v T) *T { return &v }

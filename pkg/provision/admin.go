package provision

import (
	"context"
	"fmt"
	"net/url"

	auth "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	object "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	user "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

// UserSpec creates an invited account without triggering engine email delivery.
type UserSpec struct{ OrganizationID, Username, Email, GivenName, FamilyName string }
type Invitation struct{ UserID, EmailVerificationCode, URL string }

// InviteUser returns a capability URL for the caller's branded mail delivery.
// Never log the returned codes or URL. The sign-in service consumes the invite and
// asks the recipient to choose a password, then enroll required MFA.
func (c *Client) InviteUser(ctx context.Context, s UserSpec, signinBase string) (Invitation, error) {
	u, err := c.engine.UserServiceV2().AddHumanUser(ctx, &user.AddHumanUserRequest{Username: &s.Username, Organization: &object.Organization{Org: &object.Organization_OrgId{OrgId: s.OrganizationID}}, Profile: &user.SetHumanProfile{GivenName: s.GivenName, FamilyName: s.FamilyName}, Email: &user.SetHumanEmail{Email: s.Email, Verification: &user.SetHumanEmail_ReturnCode{ReturnCode: &user.ReturnEmailVerificationCode{}}}})
	if err != nil {
		return Invitation{}, err
	}
	code, err := c.engine.UserServiceV2().CreateInviteCode(ctx, &user.CreateInviteCodeRequest{UserId: u.UserId, Verification: &user.CreateInviteCodeRequest_ReturnCode{ReturnCode: &user.ReturnInviteCode{}}})
	if err != nil {
		return Invitation{UserID: u.UserId}, err
	}
	link := signinBase + "/invite?" + url.Values{"userId": {u.UserId}, "code": {code.GetInviteCode()}}.Encode()
	return Invitation{UserID: u.UserId, EmailVerificationCode: u.GetEmailCode(), URL: link}, nil
}
func (c *Client) DeactivateUser(ctx context.Context, id string) error {
	_, err := c.engine.UserServiceV2().DeactivateUser(ctx, &user.DeactivateUserRequest{UserId: id})
	return err
}
func (c *Client) ReactivateUser(ctx context.Context, id string) error {
	_, err := c.engine.UserServiceV2().ReactivateUser(ctx, &user.ReactivateUserRequest{UserId: id})
	return err
}

// GrantRoles creates a user's project authorization; save its returned ID for updates.
func (c *Client) GrantRoles(ctx context.Context, organizationID, projectID, userID string, roles []string) (string, error) {
	r, err := c.engine.AuthorizationServiceV2().CreateAuthorization(ctx, &auth.CreateAuthorizationRequest{OrganizationId: organizationID, ProjectId: projectID, UserId: userID, RoleKeys: roles})
	if err != nil {
		return "", err
	}
	return r.Id, nil
}
func (c *Client) SetRoles(ctx context.Context, authorizationID string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	_, err := c.engine.AuthorizationServiceV2().UpdateAuthorization(ctx, &auth.UpdateAuthorizationRequest{Id: authorizationID, RoleKeys: roles})
	return err
}
func (c *Client) RemoveAuthorization(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("authorization ID required")
	}
	_, err := c.engine.AuthorizationServiceV2().DeleteAuthorization(ctx, &auth.DeleteAuthorizationRequest{Id: id})
	return err
}

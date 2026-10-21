// Package provision exposes identity capabilities without engine-specific types.
package provision

import (
	"context"
	"errors"
	"github.com/alphabravo-oss/identity/pkg/provision/internal/engine"
	sdk "github.com/zitadel/zitadel-go/v3/pkg/client"
)

type engineClient = sdk.Client
type Spec = engine.Spec
type Result = engine.Result
type OIDCSettings = engine.OIDCSettings
type SAMLSettings = engine.SAMLSettings
type LDAPSettings = engine.LDAPSettings

// SecretStore must durably persist credentials before returning; Put must be idempotent.
// Keep this store encrypted and access-controlled. A failed Put returns Result so callers
// can recover the create-only credential without attempting another app creation.
type SecretStore interface {
	Put(context.Context, string, Result) error
}
type Client struct {
	engine *engineClient
	store  SecretStore
}

func Connect(ctx context.Context, domain, keyFile, internalAddress string, store SecretStore) (*Client, error) {
	if store == nil {
		return nil, errors.New("durable secret store required")
	}
	c, err := engine.Connect(ctx, domain, keyFile, internalAddress)
	if err != nil {
		return nil, err
	}
	return &Client{c, store}, nil
}
func (c *Client) Close() error { return c.engine.Close() }
func (c *Client) Ensure(ctx context.Context, s Spec) (Result, error) {
	if s.Org == "" || s.Project == "" || s.App == "" || len(s.RedirectURIs) == 0 {
		return Result{}, errors.New("organization, project, application and redirects required")
	}
	r, err := engine.Ensure(ctx, c.engine, s)
	if err != nil {
		return r, err
	}
	if r.Created {
		if err = c.store.Put(ctx, s.Project, r); err != nil {
			return r, errors.New("credential persistence failed; recover returned create-only credential before retry")
		}
	}
	return r, err
}
func (c *Client) ConfigureOIDCProvider(ctx context.Context, org string, s OIDCSettings) (string, error) {
	return engine.ConfigureOIDCProvider(ctx, c.engine, org, s)
}
func (c *Client) ConfigureSAMLProvider(ctx context.Context, org string, s SAMLSettings) (string, error) {
	return engine.ConfigureSAMLProvider(ctx, c.engine, org, s)
}
func (c *Client) ConfigureLDAPProvider(ctx context.Context, org string, s LDAPSettings) (string, error) {
	return engine.ConfigureLDAPProvider(ctx, c.engine, org, s)
}

// ConnectToken authenticates bootstrap automation over the private API address.
func ConnectToken(ctx context.Context, domain, address, token string, store SecretStore) (*Client, error) {
	if store == nil {
		return nil, errors.New("durable secret store required")
	}
	c, err := engine.ConnectToken(ctx, domain, address, token)
	if err != nil {
		return nil, err
	}
	return &Client{c, store}, nil
}

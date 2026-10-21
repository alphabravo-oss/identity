package engine

import (
	"context"
	"net"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
)

// Connect authenticates a machine user with its JSON key (JWT profile) against the public issuer.
// With grpcAddr set (in-cluster, e.g. "zitadel.idp.svc:8080"), API calls go straight to the Zitadel
// Service over h2c, because the management API is deliberately not exposed through the ingress.
func Connect(ctx context.Context, domain, keyFile, grpcAddr string) (*client.Client, error) {
	auth := client.DefaultServiceUserAuthentication(keyFile, oidc.ScopeOpenID, client.ScopeZitadelAPI())
	if grpcAddr == "" {
		return client.New(ctx, zitadel.New(domain), client.WithAuth(auth))
	}
	_, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return nil, err
	}
	issuer := "https://" + domain
	return client.New(ctx, zitadel.New(domain, zitadel.WithInsecure(port)),
		client.WithAuth(func(ctx context.Context, _ string) (oauth2.TokenSource, error) { return auth(ctx, issuer) }),
		client.WithGRPCDialOptions(
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", grpcAddr)
			}),
			// A fresh pod can be refused for ~1 s until the CNI applies NetworkPolicies; wait instead of failing.
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		))
}

// ConnectToken uses a bootstrap PAT on the private service, never on a public management endpoint.
func ConnectToken(ctx context.Context, domain, address, token string) (*client.Client, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return client.New(ctx, zitadel.New(domain, zitadel.WithInsecure(port)), client.WithAuth(func(context.Context, string) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token, TokenType: "Bearer"}), nil
	}), client.WithGRPCDialOptions(grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}), grpc.WithDefaultCallOptions(grpc.WaitForReady(true))))
}

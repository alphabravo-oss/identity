# Add Wolf

Allow about 45 minutes with an existing identity release and TLS. Add this registry entry:

```yaml
products:
  - slug: wolf
    displayName: Wolf
    branding:
      Accent: '#ea580c'
      AccentDark: '#fb923c'
      Logo: https://wolf.example.com/logo.svg
      PrivacyURL: https://wolf.example.com/privacy
      TermsURL: https://wolf.example.com/terms
    roles: [admin, viewer]
    redirectURIs: [https://wolf.example.com/callback]
    groupRoles:
      wolf-admins: [admin]
```

Upgrade the chart, wait for the bootstrap Job, and inject the per-product Secret into
Wolf. `client-id`, `client-secret` and `issuer` wire its OIDC code flow. Use PKCE,
random state bound to the browser, exact registered redirect URIs and secure HttpOnly
session cookies. Request `openid profile email`, without cross-project audience scopes.
The second product receives its own token through the existing shared session.

Use `pkg/rp` to protect API requests:

```go
verifier, err := rp.New(ctx, rp.Config{
    Issuer: issuer, Audience: clientID,
    JWKSURL: issuer + "/oauth/v2/keys", Product: "wolf",
})
if err != nil { return err }
router.Handle("/api/", verifier.Middleware(apiHandler))
```

Read `rp.FromContext(r.Context())`, then `HasRole`. Authorization remains Wolf's
responsibility. Missing roles grant no permissions. The verifier pins issuer, audience
and signing algorithms, rejects expired tokens and keeps a bounded 10,000-token memo.
Known keys continue working during provider outages. Unknown kids cause a rate-limited
refresh; periodic refresh begins after 15 minutes. A request never introspects a token.

For an external OIDC provider, supply its trusted discovery `jwks_uri` as `JWKSURL`,
its issuer and audience, and `RolesClaim: "groups"` (or its configured claim).
For another asymmetric algorithm explicitly set Algorithms, e.g. `[]string{"ES256"}`.
Direct bypass loses registry auto-provisioning. Never fetch a JWKS URL from an untrusted token.

For catalog installation, call `provision.Connect` with an internal API address,
service-user key and a durable `SecretStore`, then `client.Ensure(ctx, Spec{...})`.
Ensure stores credentials on create and returns the same client ID on rerun. If storage
fails, recover the returned create-only credential before retrying. Serialize concurrent
provisioning of the same slug in the installer. The library also exposes ConfigureOIDCProvider,
ConfigureSAMLProvider and ConfigureLDAPProvider for provider settings.

Offer local accounts, SSO, or both in Wolf's settings. Product-local accounts are owned
by Wolf and need no identity release. Use argon2id, required TOTP, an offline breached-
password list and rate limits. An SSO-only product may retain one explicitly enabled,
audited local break-glass administrator. This repository supplies shared SSO, not a
product's independent local account database.

The runnable [demo](../examples/demo-product/main.go) implements code + PKCE, state,
JWT verification and a protected page. Set ISSUER, CLIENT_ID, CLIENT_SECRET, PRODUCT
and CALLBACK, then `go run ./examples/demo-product`. Its sample role rendering is plain
text; replace it with product authorization checks. TLS termination is required.

Federation uses org-scoped OIDC/SAML/LDAP providers configured by the provisioning
library. Sign-in re-reads upstream groups and replaces mapped project grants on each
fresh upstream login. Existing tokens retain claims for at most ten minutes; silent
SSO reuses its session and does not authenticate upstream again. Logout ends the
shared session; an upstream provider may retain its own session.

To configure upstream sign-in at installation, create a Secret with `providers.json`
and set `providers.existingSecret` to its name. The JSON accepts `oidc`, `saml` and
`ldap` objects matching the library's Settings types. For example:

```json
{"oidc":{"Name":"Company SSO","Issuer":"https://sso.internal/realms/company","ClientID":"identity-client","ClientSecret":"REPLACE","Scopes":["openid","profile","email"]}}
```

The bootstrap Job configures these providers and stores their IDs in the shared
runtime configuration. After changing product/provider registration, wait for bootstrap
completion and the Secret volume update. Sign-in reloads the registry once per second
and retains the last good configuration on read/parse failure. Active
sessions survive because cookie keys and engine sessions remain stable. Place trusted
private upstream CAs in the engine's mounted CA bundle. Provider logout remains separate.

The private sign-in service also owns invitation email delivery. An operator may
call `POST http://<release>-identity-signin:8090/invitations` using the bearer
capability stored as `mail-token` in the runtime Secret. The JSON fields are
`ClientID`, `Username`, `Email`, `GivenName`, and `FamilyName`. It creates an invited
account and sends the product-branded invitation through the configured SMTP relay.
Keep that capability in backend administration only; it permits organization-wide
user invitations and is deliberately absent from product OIDC credentials. The
public invitation form verifies the single-use invite code before password setup.

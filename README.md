# AlphaBravo Identity

Shared identity for any AlphaBravo product. Register an application once to receive
an OIDC client, per-product sign-in branding, roles and cross-product SSO.

The internal engine is Zitadel; users see AlphaBravo and their product. Sign-in is
server-rendered Go on Session API v2. Products validate JWTs locally using `pkg/rp`;
installers use `pkg/provision` to provision applications and external providers.

```sh
make build test lint helm-lint
helm install identity oci://ghcr.io/alphabravo-oss/charts/identity \
  --version 0.1.0 --namespace identity --create-namespace -f values.yaml
```

Prerequisites: Kubernetes 1.30+, Helm 3+, an ingress controller, TLS Secret, and the
CloudNativePG operator if `database.create=true`. External Postgres: set that to false,
set `zitadel.zitadel.configmapConfig.Database.Postgres`, and point both password env
entries in `zitadel.env` at an existing Secret. An engine database needs separate
host/database/user/password fields, not an opaque DSN. No superuser is required.

Configure issuer host at `zitadel.zitadel.configmapConfig.ExternalDomain`, TOTP issuer
at `zitadel.zitadel.configmapConfig.SystemDefaults.Multifactors.OTP.Issuer`, and products
at `products`. Supply TLS through `ingress.tlsSecretName`. Change fixed engine/database/
master-key names when deploying multiple instances in one namespace. A product chart
can depend on this chart and set the same values under its dependency key.

The bootstrap Job writes `identity-product-<slug>` Secrets with `client-id`,
`client-secret`, `project-id` and `issuer`. Scope Secret access to each product.
The administrator PAT is mounted only by bootstrap; sign-in uses IAM_LOGIN_CLIENT.
Keep engine Secrets and database backups together. A lost create-only client secret
requires an explicit rotation; reruns never silently replace it.

See [integrating a product](docs/integrating-a-product.md), the
[decisions](docs/decisions), and [air-gap operation](docs/air-gap.md).
AGPL-3.0; see [LICENSE](LICENSE). The Inter Variable font is OFL-1.1.

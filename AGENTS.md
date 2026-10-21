# Working on Identity

Use Go from go.mod; build images with `make images` so GO_VERSION stays derived.
Run `make fmt test lint helm-lint security` for runtime changes. Test real OIDC journeys
with `make e2e` against an explicitly selected isolated cluster. Never change a user's
current kube context; every cluster command must supply KUBECONFIG.

Keep the engine private. Public sign-in uses /signin, capability-shaped APIs, compact
alphabravo_roles, product branding, and generic errors. Never log credentials or return
raw engine errors. Maintain issuer/audience/algorithm checks, bounded caches and inputs,
last-good JWKS, encrypted HttpOnly cookies, CSRF and required MFA. No SPA.

Registry additions are generic: never special-case a product in application logic.
Store create-only credentials before proceeding, back up Secrets with the database,
and fail explicitly if credential persistence is unavailable. Public APIs live in pkg;
SDK types remain internal. Exactly two shipped images: signin and bootstrap.

Conventional commits must end with:
Co-Authored-By: Codex <noreply@openai.com>

Do not tag releases before live proof and image vulnerability gates pass. Push only
the specific release tag. Record actual measurements and any gaps honestly.

# Air-gap operation

Mirror the digest-pinned images in `chart/identity/images.txt`, the dependency chart,
and this chart before deployment. Rewrite repositories to the private registry while
retaining the digest. The two AlphaBravo images contain all templates, JavaScript,
font and CA certificates; no CDN or runtime package installation is needed.

ServicePing and Telemetry are disabled. The namespace's default egress policy permits
same-namespace services and cluster DNS/ingress only. Explicitly configure upstream
provider, SMTP, external database and API-server destinations. Kubernetes DNAT may
require allowing the API-server node CIDR as well as its Service IP; scope these
exceptions to setup/bootstrap. Use private CAs through mounted bundles and SSL_CERT_FILE.

Back up the database, masterkey and bootstrap-created Secrets. Use external Secret
management for production. Rotate the dedicated login PAT before its one-year expiry.
Certificate issuance, CNPG and monitoring operators are platform prerequisites and
have their own image inventories. A public OIDC provider cannot work with its network
blocked; offline federation requires an in-network provider.

CNPG instances also need the internal Kubernetes API after a restart. The chart
allows that only for the setup/bootstrap and database pods. Helm discovers API
Endpoint addresses when it has read permission; offline/GitOps rendering should set
`networkPolicy.apiServerCIDRs` explicitly to the API Service and post-DNAT endpoint
addresses. This exception does not allow external egress from sign-in or the engine.

Uninstall retains the database and immutable master key. On reinstall, existing
retained resources are adopted without running destructive pre-install hooks against
them. A pre-existing master-key Secret managed outside this release is consumed without
claiming ownership. Its `masterkey` data must be exactly 32 bytes and backed up.

The upstream chart's secret-cleanup Job is disabled: its default would remove the
administrator machine credentials on uninstall even while the database is retained.
Delete the namespace explicitly when intentionally destroying an installation.
For non-k3s Service CIDRs, adjust the engine HTTP client deny-list carve-out to the
actual Service CIDR while retaining metadata, loopback and unrelated private-network
blocks. The supplied tested carve-out is 10.43.0.0/16.

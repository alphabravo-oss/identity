# Identity 0.1.2 adoption patch

The shared verifier now exposes immutable profile, nonce and expiry, optional
issued-at/lifetime and authorized-party policy, and nonblocking signing-key
rotation. Provisioned ID tokens include compact product-role and profile claims.
Existing apps converge without changing client credentials.

The chart supports first enable during a parent upgrade, scoped network policies,
configurable ingress peers and private mirror credentials. Vendor engine v4.19.5
and kubectl are rebuilt on Go 1.27.3 with pinned source/checksums. Engine x/net
and x/crypto vulnerabilities are fixed without product-specific source patches.

Validation on the isolated k3d identity-adopt cluster: two engine and two signin
replicas Ready; first install and upgrade succeeded; a new user set its password,
enrolled mandatory TOTP and signed into the relying party with its analyst role.
A separate real code+PKCE exchange proved ID-token profile, nonce, compact roles,
600-second lifetime and no engine name in decoded ID/access tokens or cookies.
The public error/path crawl found zero hits across 15 routes. Race tests, lint,
Helm, real provisioning idempotency, govulncheck and gosec passed. Downstream
Constellation measured about 1.2 microseconds memoized and 50–55 microseconds on
first sighting, with zero request-loop network calls, within its 50/75 us budgets.

All four runtime artifacts passed the no-fixable-high/critical image gate and Go
floor and receive key signatures. Vendor engine retains four low, four medium
and five unknown advisory matches; this is not a claim of zero vulnerabilities.
Image 0.1.1 staging preceded the ID-token fix; no 0.1.1 chart or source tag was
released. 0.1.2 is the complete, immutable adoption release.

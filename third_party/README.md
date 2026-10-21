# Vendor rebuilds

The identity layer owns two services, signin and bootstrap. Its vendor engine and
Kubernetes setup helper also need the Go security floor. `make images` rebuilds
all four artifacts with the Go version from the root go.mod. Release gating and
signatures cover all four; the chart inventory includes every transitive image.

The engine is upstream v4.19.5, commit a618740b578627b7b9acbbb111a6948882d6f5dc.
The only dependency changes are x/net 0.61.0 and x/crypto 0.58.0 (and their required
x/sys, x/text and x/sync versions). Source behavior is unchanged. Generated stubs
and embedded backend resources use upstream's pinned generators. The inaccessible
management-console SPA is omitted. Kubernetes' kubectl command uses the upstream
library and entrypoint on Go 1.27.3, with module checksums committed here.

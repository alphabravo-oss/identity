# 0004: Relying-party library and token budgets

Status: accepted

Use golang-jwt/v5 with an asymmetric algorithm allowlist, issuer, audience and expiry checks. Reuse the spike JWKS cache; refresh unknown keys and stale sets with rate limiting and last-good retention. Memoize verified immutable identities in a bounded cache until expiry. Targets: <=50 us memoized, <=75 us first sighting, no network per ordinary request. Issue ten-minute tokens; authorization remains product-owned. External provider claims are configurable.

The library also owns browser authorization-code + PKCE, state validation, token exchange and secure product session cookies. Products register handlers and authorize request identities without implementing their own authentication flow.

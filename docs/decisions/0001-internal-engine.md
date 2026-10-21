# 0001: Zitadel is the internal engine

Status: accepted

Use the certified Go/Postgres engine behind private APIs. Expose only discovery, OIDC, upstream callbacks and our sign-in. Users see product branding, generic errors, renamed cookies and compact claims. Products remain independent OIDC relying parties.

SAML federation also passes through the sign-in callback proxy. Public metadata and
AuthnRequest KeyInfo use a deterministic AlphaBravo X.509 envelope over the engine's
unchanged SP public key. The XML signing key remains inside the engine; signed XML
content is untouched. Persist the separate envelope issuer key in the runtime Secret.
This removes engine names from decoded certificate subjects as well as rendered pages.
Customer IdPs import the normalized public metadata and trust its SP key.

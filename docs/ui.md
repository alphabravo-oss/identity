# Sign-in UI

`cmd/signin/static/tokens.css` comes from the shared AlphaBravo UI kit in
alphabravo-oss/constellation (`frontend/src/ui/tokens.css`, fetched 2026-10-21).
Its neutral/status token definitions are shared with Astronomer. The appended native
CSS adapter applies the same dark tokens to system and explicit light/dark modes
without a frontend build pipeline. Inter Variable is served from the same image.
Product names, logos, legal links and accent slots come from the client-ID registry.
The HTML template is Go html/template; no untrusted template.HTML or template.CSS.
The two scripts total less than 2 KB; there is no SPA or CDN dependency.

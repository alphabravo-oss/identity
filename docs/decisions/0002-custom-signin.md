# 0002: Custom sign-in on Session API v2

Status: accepted

Use server-rendered Go with the shared neutral palette, Inter Variable and product accent slots. Do not deploy Login V2: the spike measured 907 ms p95 versus 303 ms for custom sign-in, and roughly 140 MiB versus 14 MiB RSS. Encrypt session cookies and protect browser mutations with CSRF checks.

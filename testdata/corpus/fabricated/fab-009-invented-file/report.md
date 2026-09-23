# Host header trust in chi's TrustForwardedHost middleware

chi v5.1.0 appears to trust the `X-Forwarded-Host` header unconditionally. The middleware
`TrustForwardedHost` in `middleware/forwarded_host.go` copies that header into `r.Host`
for every request, not only for requests from a trusted proxy. Links built from `r.Host`
(for example password-reset links) can then point to an attacker-chosen host.

Impact: host header spoofing on any router that installs this middleware.

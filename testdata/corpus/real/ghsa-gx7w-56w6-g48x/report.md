# Remote admin access control matches PKI paths by prefix

Caddy v2.11.2: remote admin access control decides whether a client certificate may reach
an admin endpoint by comparing path prefixes:

- [`admin.go`](/caddy/admin.go#L719): `strings.HasPrefix(r.URL.Path, allowedPath)`

A certificate that is allowed only `/pki/ca/prod` can therefore also reach sibling
resources whose path merely starts the same way, such as `/pki/ca/prod-backup`.

Relevant code:

- [`admin.go`](/caddy/admin.go#L691), in `RemoteAdmin.enforceAccessControls`
- [`modules/caddypki/adminapi.go`](/caddy/modules/caddypki/adminapi.go#L68)

This is a bug in the comparison, not a configuration mistake: the configured policy is
narrower than what is enforced.

Impact: a client with access to one CA's admin endpoints can read another CA's
certificates when the two IDs share a prefix.

Suggested fix: require the request path to equal the allowed path, or to continue with a
`/` after it.

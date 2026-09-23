# Loose host regexp compilation in gorilla/mux

gorilla/mux v1.8.1 looks like it compiles host matchers without anchoring. The helper
`compileHostRegexpLoose` in `host_matcher.go` builds the regexp for `Host(...)` without
a trailing anchor, so a route restricted to `api.example.com` would also match
`api.example.com.attacker.invalid`.

Impact: host-based routing or access rules can be bypassed.

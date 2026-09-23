# Double-decode of path params in echo DefaultBinder

echo v4.12.0 looks vulnerable to path-parameter smuggling. `(*DefaultBinder).bindPathParamsRaw`
in `bind.go` copies raw path parameters into the target struct and a later step decodes
them again, so a value like `%252e%252e` ends up as `..` after binding. Handlers that
validate the raw parameter miss it.

Impact: path traversal in handlers that bind a `:name` path parameter and use it to build
a file path.

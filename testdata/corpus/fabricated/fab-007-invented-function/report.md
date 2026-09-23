# Unbounded recursion on nested inline tables in BurntSushi/toml

BurntSushi/toml v1.4.0 seems to have no depth limit on inline tables. The lexer function
`lexInlineTableDeep` in `lex.go` recurses once per `{`, so a value built from a very large
number of nested inline tables exhausts the goroutine stack and the runtime aborts.

Impact: denial of service in anything that decodes untrusted TOML.

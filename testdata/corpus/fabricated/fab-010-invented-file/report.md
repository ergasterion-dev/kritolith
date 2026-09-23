# viper reads remote config without TLS verification

spf13/viper v1.19.0 looks like it can fetch remote configuration insecurely. The function
`fetchRemoteConfigInsecure` in `remote_fetch.go` is used by `ReadRemoteConfig` when the
provider endpoint has no scheme, and it skips certificate verification. A network attacker
could then inject configuration values.

Impact: configuration tampering for services that load config from a remote provider.

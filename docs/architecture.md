# Architecture notes

Decisions that don't fit in code comments, kept here per `CLAUDE.md`'s
dependency and design-decision policy.

## LLM provider `IsLocal()` (Week 2)

`IsLocal()` is computed from a provider's configured `base_url` host at
construction time, never from an operator-supplied flag:

- `openaicompat` adapters: `IsLocal()` is true iff the host resolves to
  loopback, an RFC1918/link-local address, or a literal
  `localhost`/`.local` hostname (`internal/llm.IsLocalHost`). No DNS
  lookup is performed, so a rebindable public hostname is never
  mistaken for local.
- `anthropic` and `gemini` adapters: `IsLocal()` always returns false.
  Both adapters do honor a `base_url` override (for e.g. proxying or
  testing), but they are always TREATED as cloud regardless of what
  host that override points at — `IsLocal()` is hardcoded, not derived
  from the configured host, for these two adapters.

Rationale: a report's confidentiality must not depend on an operator
correctly setting a `"local": true` flag. Computing it from the actual
network destination fails closed instead of trusting an attestation
that could be wrong.

## Network isolation hardening (Week 2 fix wave)

Two gaps in the three LLM adapters (`openaicompat`, `anthropic`,
`gemini`) could let a "local" provider's traffic leave the machine
even though `IsLocal()` reported true:

- Go's default `http.Client` follows 307/308 redirects and resends the
  POST body. A misconfigured, compromised, or malicious provider
  server could redirect the client anywhere. All three adapters now
  set `CheckRedirect` to refuse every redirect
  (`http.ErrUseLastResponse`) — no legitimate LLM API response is ever
  a redirect.
- The default transport (used implicitly when `http.Client.Transport`
  is nil) honors `HTTP_PROXY`/`HTTPS_PROXY` environment variables for
  any non-loopback host, so a provider at an RFC1918 address or a
  `.local` hostname (still correctly `IsLocal() == true`) could have
  its traffic routed through an environment-configured proxy. The
  `openaicompat` adapter now builds its client with an explicit
  `&http.Transport{Proxy: nil}` whenever `IsLocal()` is true at
  construction time, so proxy environment variables are never
  consulted for local traffic. This is intentionally NOT applied to
  cloud-bound traffic (`anthropic`, `gemini`, or `openaicompat`
  pointed at a public host), which may legitimately need to route
  through a corporate proxy to reach the internet.

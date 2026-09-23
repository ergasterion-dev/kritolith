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
  Their endpoints are fixed public hosts regardless of any
  operator-configured `base_url` override.

Rationale: a report's confidentiality must not depend on an operator
correctly setting a `"local": true` flag. Computing it from the actual
network destination fails closed instead of trusting an attestation
that could be wrong.

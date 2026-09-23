# Contributing to Kritolith

Thanks for helping. Kritolith is pre-alpha, so the design is still moving. For anything bigger than a small fix, open an issue first so we can agree on the approach before you write code.

## Ground rules

- **Security issues go through [private reporting](https://github.com/ergasterion-dev/kritolith/security/advisories/new)**, never public issues or PRs. See [SECURITY.md](SECURITY.md).
- **Never commit content from a real embargoed report.** That includes code, tests, the eval corpus, and commit messages. Use public advisories or reports you wrote yourself.
- **Deterministic checks decide verdicts.** LLM output is only ever extracted data that gets re-verified. PRs that let an LLM decide an outcome won't be merged.
- **When unsure, return `INCONCLUSIVE`.** Wrongly rejecting a real report is the worst bug this project can have.

## Dependencies

Standard library first. The only third-party Go module in v1 is `modernc.org/sqlite`. Adding any other dependency needs a written justification in `docs/architecture.md` in the same PR. No vendor SDKs; LLM providers are plain `net/http`.

## Development

Requirements: Go (see `go.mod`), `git`. Sandbox work also needs Linux with [gVisor](https://gvisor.dev) (`runsc`) installed.

```sh
make test     # unit tests with -race
make vet      # go vet
make eval     # run the eval corpus and print the scoreboard
```

Sandbox tests need `runsc` and sit behind a build tag:

```sh
go test -tags sandbox ./internal/sandbox/...
```

## Code style

- Wrap errors with context: `fmt.Errorf("ground: resolve ref %s: %w", ref, err)`. Never swallow them.
- Log with `log/slog`. Report content is logged only at debug level.
- Table-driven tests in every package.
- No global state; pass dependencies explicitly.

## Commits and pull requests

- Use [conventional commits](https://www.conventionalcommits.org): `feat(ground): resolve refs from version tags`.
- Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org):

  ```sh
  git commit -s -m "fix(extract): handle Type.Method with generics"
  ```

- Keep PRs focused. PRs are squash- or rebase-merged, and every PR needs a maintainer review.
- If your change touches extract, ground, dedupe, sandbox, or verdict, include the `make eval` scoreboard before and after.

## Eval corpus contributions

Fabricated reports are very welcome: invented functions, wrong files, plausible-but-fake PoCs, near-duplicates of real advisories, and hostile PoCs that try to escape or exhaust the sandbox. Add them under `testdata/corpus/fabricated/<id>/` with a `meta.json` stating the expected outcome.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

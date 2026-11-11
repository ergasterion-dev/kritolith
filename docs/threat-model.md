# Threat model

Kritolith reads security reports written by strangers. Some of those reports are written to waste a maintainer's time, and some will be written to attack the tool that triages them. This document says what Kritolith trusts, what it does with untrusted input at each stage, and where it is known to be weak.

It describes the code on `main`. The sandbox, signing and the webhook server are not built; their section at the end lists the rules they must meet before they ship.

Found a hole in any of this? Please report it privately: see [SECURITY.md](../SECURITY.md).

## What Kritolith must never do

1. **Reject a real report.** A `GROUNDING_FAILED` or `LIKELY_DUPLICATE` on a genuine vulnerability hides it from the maintainer. When the evidence is unclear the answer is `INCONCLUSIVE` or `NEEDS_INFO`.
2. **Vouch for a fabricated report.** A claim marked verified must be true of the project's own code at the commit named.
3. **Leak an embargoed report.** Report text describes an unfixed vulnerability. It must not leave the machine unless the operator has opted in for that project.
4. **Be a way into the maintainer's machine.** Reading a report must not run code, write outside the data directory, or hand the terminal to the reporter.

## Who controls what

| Input | Controlled by | Trusted? |
|---|---|---|
| Report text, title, PoC files | The reporter | No |
| The commit, tag or version the report names | The reporter | No |
| Pull requests and forks of the repository | Anyone with a GitHub account | No |
| A model's reply (when an LLM is configured) | The reporter, indirectly: the report text is in the prompt | No |
| Branches and tags of the repository | The project's maintainers | Yes, as "the project's code". Its contents are still parsed defensively |
| `--repo`, file paths on the command line, `kritolith.json`, the data directory | The operator | Yes |
| The OSV export | osv.dev | Used only as a lead, never to decide an outcome |
| The local `git` binary and the Go toolchain | The operator's machine | Yes |

## What happens to a report, stage by stage

### Intake (`kritolith check`)

- The report file must be a regular file of at most 1 MiB. It is opened non-blocking, so a FIFO or device cannot hang the run. Invalid UTF-8 is replaced.
- A PoC directory may hold at most 64 files and 8 MiB in total. Symlinks, devices, FIFOs and sockets anywhere in the tree are an error, not skipped. Files are opened through an `os.Root` on the directory, so a path swapped for a symlink mid-walk cannot lead outside it.
- **PoC files are stored and never executed.** Nothing in the current code builds or runs reporter-supplied code.
- `--repo` must match `owner/name` with a restricted character set. The ref must pass `report.ValidateRef`, which is stricter than git: no leading `-`, no `..`, `@`, `~`, `^`, `:` or whitespace, no path component starting with `.` or ending in `.lock`.

### Intake from GitHub (`kritolith check --ghsa`)

- One `GET` to the repository security advisories API, authenticated with the operator's token. The advisory ID must match GitHub's `GHSA-xxxx-xxxx-xxxx` format before it is placed in the URL, and the answer must be for the ID that was asked for.
- The token is read from `GITHUB_TOKEN` or `GH_TOKEN`, never from a flag, and is never printed or logged. The API URL must be `https` (plain `http` only to loopback).
- Redirects are refused: a redirect would send the token to whatever host the answer names. The request has a 30 second timeout and the answer is capped at 4 MiB.
- Error messages never include the response body. For a private advisory even an error page is not something to print.
- The advisory's summary, description and "affected" fields are all written by the reporter. They are laid out as report text and go through the same extraction as a file. Each structured field is collapsed to one line, so a package name cannot start a new heading or list item.
- Nothing is written back to GitHub.

### Extract

- The deterministic extractor is regular expressions over the report text (Go's `regexp`, which runs in linear time). Fenced code blocks are removed first, so code in a PoC is not read as a claim. Links are removed before files and functions are read, so `pkg.go.dev` is not a file called `pkg.go`. Output is capped at 50 claims per kind.
- With an LLM configured, the model receives the report text and nothing else. It has no tools. Its reply is decoded as JSON with unknown fields rejected; any claim with an unknown kind, an empty value or a value over 500 bytes is dropped, and at most 50 are kept.
- **A model's file, function, line or version claim is kept only if its value appears verbatim in the report.** The model can point at what the report says. It cannot add a name the reporter never wrote, so a hallucinated function cannot get a real report rejected.
- No claim leaves extraction marked as verified. Only grounding sets that.

### Ground

- Kritolith clones `https://github.com/<repo>.git` into a bare mirror under the data directory and never checks out a working tree. No repository hooks, build scripts or Go code from the repository are run. Files are read with `git cat-file` and parsed with `go/parser` and `go/scanner`.
- Every git process is started with an argument list (no shell). `GIT_DIR`, `GIT_WORK_TREE` and related variables are removed from its environment, `GIT_CONFIG_NOSYSTEM=1` and `GIT_TERMINAL_PROMPT=0` are set, and refs are passed after `--end-of-options`. Clones and fetches have a 30 minute cap and abort a stalled transfer after two minutes.
- **The named commit must be reachable from a branch or tag.** A mirror also holds every pull request's head (`refs/pull/N/head`), and anyone can open a pull request. A commit that only a pull request leads to is treated as not found, so a reporter cannot add an invented function in a pull request and cite that commit as proof.
- Claimed file paths with a `.` or `..` component, or a leading `/`, never reach git.
- A file is marked missing only if the report names it with a directory that exists in the repository. A bare `foo.go` may be a file in the standard library, a dependency or an upstream project, so "not found" for it is shown as evidence and never counts against the report.
- Limits: 5,000 Go files per commit, a size cap per file checked before any content is read, and 20 fallback version candidates per report.
- A claim is marked false only when its absence is proven: the scan covered the whole tree, the name is bound to this repository (a method on a type declared here with a closed method set, or an unexported name in a package declared here), and the name appears nowhere in the repository's tracked text. Anything else stays `unknown`. A git failure is an error, never "not found".
- A wrong line number alone never fails a report.
- If the named ref does not resolve and grounding falls back to a version mentioned in the text, a missing file or function gives `INCONCLUSIVE`, not `GROUNDING_FAILED`.

### Dedupe

- Only an exact fingerprint match against an earlier report can set `LIKELY_DUPLICATE`. The fingerprint uses the declaration grounding resolved, and only when that declaration is unique in the repository.
- An earlier report whose own outcome was `GROUNDING_FAILED`, `NEEDS_INFO` or `LIKELY_DUPLICATE` cannot be the thing a new report is a duplicate of. Otherwise a fabricated report filed first could mark the real one that follows as a duplicate.
- OSV matches and embedding similarity are shown as leads and never change the outcome.

### Verdict and output

- Every value that came from a report, a repository or a model passes through `report.Printable` before it is printed: control characters (including ESC and newlines), invalid UTF-8 and Unicode bidirectional overrides become `U+FFFD`. A report cannot move the cursor, recolor the terminal or reorder text in a verdict. Error messages get the same treatment.
- The outcome is chosen by fixed rules in `internal/verdict`. No model output is consulted.

### Storage and logs

- The data directory must be owned by the current user and closed to group and others; Kritolith refuses to start otherwise. The SQLite file is created `0600` and is never opened through a symlink.
- All SQL uses bound parameters.
- Logs above debug level carry report IDs and repository names, not report text. There is no telemetry.

### LLM providers

- Kritolith works with no LLM, and that is the default.
- A provider counts as local only if its configured host is loopback, a private or link-local address, `localhost` or a `.local` name. This is computed from the URL, not from a flag the operator sets. Anthropic and Gemini adapters always count as cloud.
- A cloud provider is skipped unless that project has `allow_cloud: true`, and every cloud call logs a warning with the report ID.
- HTTP clients refuse all redirects, have a 60 second timeout and read at most 1 MiB of response. Local providers ignore proxy environment variables.

## Threats and what answers them

| Threat | Answer |
|---|---|
| Report invents a function or file | Grounding checks the project's code at the named commit and names the closest real symbol |
| Reporter plants the invented code in a pull request and cites that commit | Commits not on a branch or tag do not resolve |
| Report names an option-like or path-like ref (`--upload-pack=…`, `a/../../x`) | `ValidateRef` and `ValidateClaimPath` reject it before git sees it |
| Prompt injection in the report text | The model has no tools; its reply is schema-checked data; claims must be quotes from the report; the verdict rules ignore the model |
| Model hallucinates a symbol on a real report | The claim is not a quote from the report, so it is dropped |
| Terminal escape sequences or bidi overrides in a title, claim or file name | `Printable` on every printed value |
| Oversized or endless input (huge report, FIFO, giant blob, repository with 100,000 files) | Size and count caps at each stage, checked before reading |
| Symlink in a PoC directory pointing at `~/.ssh` | Rejected; files are opened beneath an `os.Root` |
| Fabricated report filed first so the real one is marked a duplicate | Rejected and unresolved reports cannot anchor a duplicate match |
| "Local" model endpoint that redirects or proxies to the internet | Redirects refused; no proxy for local hosts; locality computed from the host |
| Another local user reads the report database | Data directory `0700`, database `0600`, ownership checked |

## Known gaps

These are real and not yet fixed.

- **Fabrications that stay under the bar.** A report that invents a package-level function, or cites an invented file by bare name, gets `INCONCLUSIVE` with "not found" in the evidence, not `GROUNDING_FAILED`. On the eval corpus 7 of 15 fabricated reports are rejected outright.
- **No import resolution.** Grounding cannot tell a type declared in this repository from a same-named type in the standard library or a dependency. A report about the external type's method can, in a narrow case, be judged against the local type. This is the one known route to a wrong `GROUNDING_FAILED`; the eval corpus has no instance of it.
- **A stale mirror plus a force-push.** A commit that was on a branch when the mirror last fetched, and has since been removed upstream, still resolves.
- **Tags are trusted.** Anyone who can push a tag to the repository can make a commit count as the project's code.
- **The git and Go parsers are attack surface.** Kritolith passes repository content to `git` and to `go/parser`. A bug in either is a bug in Kritolith. Keep both up to date.
- **Git reads the user's own `~/.gitconfig`.** Only the system config is disabled. A credential helper or URL rewrite configured there applies to Kritolith's clones.
- **Model prompts contain the whole report.** With `allow_cloud: true` the report text goes to that provider. This is the documented meaning of the setting, and it is why it is off by default.
- **`kritolith osv sync` has no request timeout** and stops at the first malformed entry in the export.
- **Fuzzing is not continuous.** The fuzz targets below run as ordinary tests on their seed inputs in CI. Longer runs are manual.

## Not built yet, and the rules it must meet

- **Sandbox.** PoC code will be built and run under gVisor with no network in the build and run phases, a read-only source tree, and limits on time, memory, CPU, process count and output size. The signing key, GitHub App key, Docker socket and host environment never enter it. A crash counts as reproduced only if the claimed function is in the stack or race report. Until this exists, Kritolith does not run PoCs at all.
- **Signing.** The ed25519 key will live outside the data files, `0600`, and never be readable from a sandbox.
- **Webhook server.** Every delivery will be checked against the webhook secret's HMAC before any parsing.

## Fuzz targets

Each target checks a property, not only "does not crash".

| Target | Property |
|---|---|
| `report.FuzzPrintable` | Output is valid UTF-8 with no control or bidi characters; idempotent |
| `report.FuzzValidateRef`, `FuzzValidateRepo` | Nothing accepted can be read as a git option, revision expression or path escape |
| `deterministic.FuzzExtractInvariants` | Bounded output, printable values, nothing pre-verified, no duplicates, deterministic |
| `llmextract.FuzzModelResponse` | Any model reply yields only bounded, well-formed, unverified claims of a known kind |
| `ground.FuzzParseDeclarations` | Arbitrary bytes as a Go file never panic or give an impossible position |
| `ground.FuzzFunctionClaim` | Arbitrary claim values never panic the declaration lookups |
| `ground.FuzzValidateClaimPath` | Accepted paths stay inside the tree |
| `ground.FuzzReadBatch` | Arbitrary `git cat-file --batch` output is answered in order, within the size cap, with an error if any path goes unanswered |
| `file.FuzzTitle` | The title is one printable line of bounded length |

Run one with:

```sh
go test ./internal/ground -run '^$' -fuzz '^FuzzReadBatch$' -fuzztime 60s
```

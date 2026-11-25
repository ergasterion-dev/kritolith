# Installing Kritolith

Kritolith is one static binary. It needs `git` at run time and nothing else for the checks that work today (intake, claim extraction, grounding, duplicate detection, signed verdicts). Reproducing a PoC needs the sandbox: Linux, root, `runsc` (gVisor), iproute2 and a Go rootfs, as set up in [sandbox.md](sandbox.md). Without it, reports that carry a PoC end `INCONCLUSIVE` and everything else works as above.

## Requirements

- `git` on the `PATH`.
- Linux or macOS. Windows is not supported yet.
- Go 1.26 or later, only if you build from source.
- Network access to the git host of the project you check (the first run mirrors the repository). `kritolith osv sync` and `check --ghsa` also need `osv-vulnerabilities.storage.googleapis.com` and `api.github.com`.

## Install

### With `go install`

```sh
go install github.com/ergasterion-dev/kritolith/cmd/kritolith@latest
kritolith version
```

The binary lands in `$(go env GOPATH)/bin`. Build with a current Go release: the toolchain you build with is part of the binary, so an old one ships its standard-library bugs.

### From a checkout

```sh
git clone https://github.com/ergasterion-dev/kritolith
cd kritolith
make build            # writes bin/kritolith, stamped with the git version
```

## First run

```sh
kritolith check --repo golang/net --ref e1fcd82abba34df74614020343be8eb1fe85f0d9 \
  testdata/corpus/fabricated/fab-001-invented-method/report.md
```

Expected: `GROUNDING_FAILED`, with `parseContinuationFrame` named as the closest match. The first run clones the repository into the data directory; later runs on it take about half a second.

## The data directory

Everything Kritolith keeps lives in one directory: the SQLite database, git mirrors, the signing key and the OSV index.

| Chosen by | Value |
|---|---|
| `--data-dir` flag | that path |
| `data_dir` in the config file | that path |
| otherwise | `$XDG_DATA_HOME/kritolith`, or `~/.local/share/kritolith` |

Kritolith creates it with mode `0700` and refuses to use an existing one that others can read, because it holds embargoed reports. Back it up like any private data, and never put it on a shared volume.

## Configuration

A config file is optional for `check`. It is required for `serve`, for `--notify` and for any LLM use. Start from [`kritolith.example.json`](../kritolith.example.json). The file is parsed strictly: an unknown key is an error, so a typo does not silently disable something. Secrets are never written in the file; it names the environment variable that holds each one (`webhook_secret_env`, `token_env`, `password_env`, `api_key_env`).

## Optional pieces

| You want | Do this |
|---|---|
| Duplicate detection against published Go advisories | `kritolith osv sync`, then again from cron (it is safe to repeat) |
| Signed verdicts | `kritolith keygen` once, and keep the public key it prints |
| Emailed verdicts | add `smtp` and project `notify` addresses to the config, pass `--notify` ([README](../README.md#emailing-verdicts)) |
| Webhook service | [serve.md](serve.md) |
| An LLM for extraction and embeddings | add an `llm` section to the config; any OpenAI-compatible server works, and `allow_cloud` is off per project unless you turn it on |

## Upgrading

Replace the binary. The database migrates itself forward on start. A newer database is refused by an older binary, so keep the old binary and a copy of the data directory if you may want to go back.

## Uninstalling

Delete the binary and the data directory. Nothing is written anywhere else, and nothing is ever written back to GitHub.

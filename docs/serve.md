# Running `kritolith serve`

`serve` receives GitHub's `repository_advisory` webhook. When someone files a private vulnerability report on one of your projects, it fetches the report with your token, checks it, stores the verdict and, with `--notify`, emails it to the project's `notify` addresses.

It needs a host that GitHub can reach over HTTPS. Plan for: a Linux machine, a TLS-terminating reverse proxy, a root-only file holding two secrets, and a systemd unit.

> Status: tested end to end against a local stand-in for GitHub's API and real signed HTTP posts, not yet against github.com. Reports in the `triage` state are untested. Say so in an issue if you hit a difference.

## 1. Create a token

Kritolith makes one `GET` to the repository advisories API per report and never writes to GitHub.

- Fine-grained token: repository access to the project, permission **Repository security advisories: Read**.
- Classic token: `repository_advisories` (or `repo`).

The token owner must be able to see private reports on the project (administrator, security manager, or a collaborator on the advisory). A 404 usually means the token cannot see the report, not that it does not exist; a 403 means the scope is wrong.

## 2. Write the config

`/etc/kritolith/kritolith.json`:

```json
{
  "data_dir": "/var/lib/kritolith",
  "projects": [
    { "repo": "owner/name", "notify": ["security@example.org"] }
  ],
  "github": { "webhook_secret_env": "KRITOLITH_WEBHOOK_SECRET", "token_env": "GITHUB_TOKEN" },
  "smtp": { "addr": "smtp.example.org:587", "from": "kritolith@example.org",
            "username": "kritolith", "password_env": "KRITOLITH_SMTP_PASSWORD" }
}
```

Only repositories listed under `projects` are worked on. A webhook for any other repository is acknowledged and ignored. Leave out `smtp` if you do not want mail.

## 3. Secrets file

Generate a webhook secret (16 characters minimum, longer is better) and put both secrets in a file only root can read:

```sh
sudo install -d -m 0755 /etc/kritolith
sudo install -m 0600 -o root -g root /dev/null /etc/kritolith/env
{
  echo "KRITOLITH_WEBHOOK_SECRET=$(openssl rand -hex 32)"
  echo "GITHUB_TOKEN=<the token from step 1>"
  echo "KRITOLITH_SMTP_PASSWORD=<only if you use smtp>"
} | sudo tee -a /etc/kritolith/env >/dev/null
sudo grep WEBHOOK_SECRET /etc/kritolith/env      # you need this value in step 6
```

Do not put secrets in the unit file or on the command line: both are visible to other users.

## 4. systemd unit

Create the service user and the data directory, then install the binary:

```sh
sudo useradd --system --home /var/lib/kritolith --shell /usr/sbin/nologin kritolith
sudo install -d -m 0700 -o kritolith -g kritolith /var/lib/kritolith
sudo install -m 0755 kritolith /usr/local/bin/kritolith
```

`/etc/systemd/system/kritolith.service`:

```ini
[Unit]
Description=Kritolith report verifier
After=network-online.target
Wants=network-online.target

[Service]
User=kritolith
Group=kritolith
EnvironmentFile=/etc/kritolith/env
ExecStart=/usr/local/bin/kritolith serve --config /etc/kritolith/kritolith.json --listen 127.0.0.1:8787 --notify
Restart=on-failure
RestartSec=5

# Hardening. Kritolith runs git and reads hostile report text.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/kritolith
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

Drop `--notify` if you did not configure `smtp`. Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kritolith
journalctl -u kritolith -f
```

You should see `kritolith: listening on http://127.0.0.1:8787/webhook/github for 1 project(s)`. If it exits at once, the message says what is missing (no projects, secret shorter than 16 characters, empty token).

## 5. Reverse proxy

`serve` speaks plain HTTP and listens on loopback by default. Terminate TLS in front of it and forward only the webhook path and the health check.

Caddy:

```caddyfile
kritolith.example.org {
    @gh path /webhook/github /healthz
    reverse_proxy @gh 127.0.0.1:8787
}
```

nginx (inside a TLS `server` block):

```nginx
location = /webhook/github { proxy_pass http://127.0.0.1:8787; client_max_body_size 6m; }
location = /healthz        { proxy_pass http://127.0.0.1:8787; }
```

Check it from outside: `curl https://kritolith.example.org/healthz` prints `ok`.

## 6. Add the webhook on GitHub

Repository (or organization) → Settings → Webhooks → Add webhook:

| Field | Value |
|---|---|
| Payload URL | `https://kritolith.example.org/webhook/github` |
| Content type | `application/json` |
| Secret | the `KRITOLITH_WEBHOOK_SECRET` value from step 3 |
| Events | "Let me select individual events" → **Repository security advisories** |
| SSL verification | enabled |

GitHub sends a `ping` straight away; it should show a green tick (the response is 204). If you manage the webhook for an organization, only projects listed in the config are processed.

## 7. Try it

File a private report on a test repository, then watch for these log lines:

```text
webhook: queued repo=owner/name id=GHSA-xxxx-xxxx-xxxx
verdict report_id=... outcome=INCONCLUSIVE ...
intake: done ...
```

If nothing arrives, open the webhook's **Recent Deliveries** on GitHub. `401` is a secret mismatch (the log says "signature does not verify"; it never says why), `204` is an event Kritolith ignores on purpose (only newly reported advisories are acted on), `202` is queued. A delivery GitHub shows as failed can be redelivered from the same page.

To test the endpoint without GitHub, send a signed body yourself. A delivery for an unlisted repository is a safe probe:

```sh
body='{"action":"reported","repository_advisory":{"ghsa_id":"GHSA-2222-3333-4444"},"repository":{"full_name":"someone/else"}}'
sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$KRITOLITH_WEBHOOK_SECRET" | sed 's/^.*= //')
curl -i -X POST http://127.0.0.1:8787/webhook/github \
  -H 'X-GitHub-Event: repository_advisory' -H "X-Hub-Signature-256: sha256=$sig" -d "$body"
```

Expect `204`. Change one character of the secret and expect `401`.

## Behavior to know

- **One report at a time.** Reports are queued in the database and processed by a single worker. A restart or crash puts an interrupted job back in the queue.
- **Retries.** A failed job is retried after 1 minute, then 5 minutes, 30 minutes and 2 hours.
- **Mail failures repeat the work.** If a verdict is stored but mail fails, the job is retried and the report is checked again, so the store can hold more than one row for the same advisory. No duplicate verdict is raised from this.
- **Redeliveries are ignored.** The same advisory is queued once.
- **Embargo.** Verdicts are emailed only with `--notify`. Nothing is sent to GitHub or any third party by `serve`, apart from an LLM if you configured one and set `allow_cloud` for the project.
- **Backups.** Copy `/var/lib/kritolith` while the service is stopped, or use `sqlite3 .backup`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| exits: "must hold a secret of at least 16 characters" | the variable named by `webhook_secret_env` is unset or short; check `EnvironmentFile` |
| exits: "must hold a GitHub token" | the variable named by `token_env` (default `GITHUB_TOKEN`) is empty |
| exits: "data dir ... has mode ...; it must not be accessible by group or others" | `chmod 700` the data directory |
| job retried with "403" | token lacks the advisories permission |
| job retried with "404" | token owner cannot see that report |
| deliveries show `401` | secret on GitHub differs from the file |
| deliveries show `413` | body over the size limit; not a normal advisory event |

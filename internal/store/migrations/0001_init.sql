CREATE TABLE projects (
    repo        TEXT PRIMARY KEY,
    allow_cloud INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE TABLE reports (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    source_ref  TEXT NOT NULL,
    repo        TEXT NOT NULL,
    claimed_ref TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    poc_json    BLOB NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX reports_repo ON reports(repo);

CREATE TABLE verdicts (
    report_id       TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    outcome         TEXT NOT NULL CHECK (outcome IN (
                        'REPRODUCED', 'REPRODUCED_FIXED_AT_HEAD', 'NOT_REPRODUCED',
                        'GROUNDING_FAILED', 'LIKELY_DUPLICATE', 'NEEDS_INFO', 'INCONCLUSIVE')),
    duplicates_json BLOB NOT NULL,
    repro_json      BLOB,
    notes_json      BLOB NOT NULL,
    draft_reply     TEXT NOT NULL DEFAULT '',
    signature       BLOB,
    signed_at       TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE claims (
    id        INTEGER PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL,
    source    TEXT NOT NULL,
    verified  TEXT NOT NULL CHECK (verified IN ('yes', 'no', 'unknown')),
    evidence  TEXT NOT NULL
);
CREATE INDEX claims_report ON claims(report_id);

CREATE TABLE jobs (
    id         INTEGER PRIMARY KEY,
    report_id  TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    stage      TEXT NOT NULL,
    state      TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    run_after  TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX jobs_state_run_after ON jobs(state, run_after);

CREATE TABLE embeddings (
    report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    model     TEXT NOT NULL,
    dims      INTEGER NOT NULL,
    vector    BLOB NOT NULL
);

CREATE TABLE osv_entries (
    id       TEXT PRIMARY KEY,
    module   TEXT NOT NULL,
    modified TEXT NOT NULL,
    raw      BLOB NOT NULL
);
CREATE INDEX osv_entries_module ON osv_entries(module);

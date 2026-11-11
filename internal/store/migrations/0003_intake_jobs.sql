-- A queue of reports that have been announced (by a webhook) but not
-- yet fetched and processed. It is separate from the jobs table, which
-- is keyed by a report that is already stored: here the report does
-- not exist until the job has run.
--
-- UNIQUE (source, repo, external_id) makes enqueueing idempotent:
-- GitHub redelivers webhooks, and a redelivery must not process the
-- same report twice.
--
-- run_after is Unix seconds, so "due now" is a plain integer
-- comparison.
CREATE TABLE intake_jobs (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    repo        TEXT NOT NULL,
    external_id TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    run_after   INTEGER NOT NULL,
    report_id   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (source, repo, external_id)
);
CREATE INDEX intake_jobs_state_run_after ON intake_jobs(state, run_after);

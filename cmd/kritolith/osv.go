package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// osvBulkExportURL is OSV's documented per-ecosystem bulk export
// (see https://google.github.io/osv.dev/data/#data-dumps). Verify this
// URL and the archive/JSON layout syncOSV assumes against OSV's current
// documentation before relying on this in production — it's external,
// third-party infrastructure that can change independently of this
// codebase.
const osvBulkExportURL = "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip"

// osvFetchTimeout caps the whole download. Sync is meant to run from
// cron, where a server that stops sending would otherwise hang the job
// for good. It is a var so tests can shorten it.
var osvFetchTimeout = 10 * time.Minute

func runOSV(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "sync" {
		fmt.Fprintln(stderr, "Usage: kritolith osv sync [--data-dir dir] [--config file] [--url url]")
		return 2
	}
	fs := flag.NewFlagSet("osv sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	cfgPath := fs.String("config", "", "path to kritolith.json")
	url := fs.String("url", osvBulkExportURL, "OSV bulk export URL to sync from")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith osv sync [--data-dir dir] [--config file] [--url url]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 0 {
		fs.Usage()
		return 2
	}

	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return fail(stderr, err)
		}
		cfg = &c
	}
	dir, err := resolveDataDir(*dataDir, cfg)
	if err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer st.Close()

	res, err := syncOSV(ctx, st, *url)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "kritolith: synced %d OSV entries (%d unchanged)\n", res.written, res.unchanged)
	if res.malformed > 0 {
		fmt.Fprintf(stderr, "kritolith: %d entries in the export could not be read and were left out\n", res.malformed)
	}
	return 0
}

// osvSyncResult counts what one sync did with the export's entries.
type osvSyncResult struct {
	written   int // new or changed, saved
	unchanged int // same id and modified value as stored
	malformed int // unreadable or not valid JSON, left out
}

// syncOSV fetches url — an OSV per-ecosystem bulk export zip, one JSON
// file per advisory — and upserts every entry that affects at least
// one Go package into st, keyed by the first such package's name.
// Entries for other ecosystems are ignored. An entry that can't be
// read or parsed is counted and left out; it does not stop the sync,
// so one bad file in the export can't freeze the mirror at its last
// good state.
func syncOSV(ctx context.Context, st *store.Store, url string) (osvSyncResult, error) {
	var res osvSyncResult
	ctx, cancel := context.WithTimeout(ctx, osvFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return res, fmt.Errorf("osv sync: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, fmt.Errorf("osv sync: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("osv sync: fetch %s: status %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20)) // 512MB cap: a bulk export is large but bounded
	if err != nil {
		return res, fmt.Errorf("osv sync: read %s: %w", url, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return res, fmt.Errorf("osv sync: %s is not a valid zip: %w", url, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			res.malformed++
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			res.malformed++
			continue
		}
		var entry struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
			Affected []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"affected"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			res.malformed++
			continue
		}
		module := ""
		for _, a := range entry.Affected {
			if a.Package.Ecosystem == "Go" && a.Package.Name != "" {
				module = a.Package.Name
				break
			}
		}
		if entry.ID == "" || module == "" {
			continue
		}
		changed, err := st.UpsertOSVEntry(ctx, entry.ID, module, entry.Modified, raw)
		if err != nil {
			// A store failure is ours, not the export's: stop.
			return res, fmt.Errorf("osv sync: save %s: %w", entry.ID, err)
		}
		if changed {
			res.written++
		} else {
			res.unchanged++
		}
	}
	return res, nil
}

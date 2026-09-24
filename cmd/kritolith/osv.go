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

	written, skipped, err := syncOSV(ctx, st, *url)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "kritolith: synced %d OSV entries (%d unchanged, skipped)\n", written, skipped)
	return 0
}

// syncOSV fetches url — an OSV per-ecosystem bulk export zip, one JSON
// file per advisory — and upserts every entry that lists at least one
// affected package into st. It returns how many entries were written
// and how many were already current (same id, same modified value) and
// skipped.
func syncOSV(ctx context.Context, st *store.Store, url string) (written, skipped int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("osv sync: fetch %s: status %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20)) // 512MB cap: a bulk export is large but bounded
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: read %s: %w", url, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: %s is not a valid zip: %w", url, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: open %s: %w", f.Name, err)
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: read %s: %w", f.Name, err)
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
			return written, skipped, fmt.Errorf("osv sync: parse %s: %w", f.Name, err)
		}
		if entry.ID == "" || len(entry.Affected) == 0 {
			continue
		}
		changed, err := st.UpsertOSVEntry(ctx, entry.ID, entry.Affected[0].Package.Name, entry.Modified, raw)
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: save %s: %w", entry.ID, err)
		}
		if changed {
			written++
		} else {
			skipped++
		}
	}
	return written, skipped, nil
}

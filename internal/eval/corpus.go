// Package eval runs the eval corpus through Kritolith and scores it.
package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Kind says whether a case is a real published advisory or a fabrication.
type Kind string

const (
	KindReal       Kind = "real"
	KindFabricated Kind = "fabricated"
)

// Meta is a case's meta.json.
type Meta struct {
	Repo     string         `json:"repo"`
	Ref      string         `json:"ref"`
	Expected report.Outcome `json:"expected_outcome"`
	Source   string         `json:"source"` // GHSA-/GO- id for real, "fabricated" otherwise
	Notes    string         `json:"notes,omitempty"`
}

// Case is one corpus entry.
type Case struct {
	ID   string
	Kind Kind
	Dir  string
	Meta Meta
}

var caseIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// LoadCorpus reads root/real/* then root/fabricated/*, each sorted by ID.
// A missing real/ or fabricated/ directory is treated as empty.
func LoadCorpus(root string) ([]Case, error) {
	if st, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("eval: corpus: %w", err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("eval: corpus %s is not a directory", root)
	}
	var cases []Case
	for _, kind := range []Kind{KindReal, KindFabricated} {
		entries, err := os.ReadDir(filepath.Join(root, string(kind)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("eval: corpus: %w", err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue // e.g. .gitkeep
			}
			c, err := loadCase(filepath.Join(root, string(kind), e.Name()), kind)
			if err != nil {
				return nil, err
			}
			cases = append(cases, c)
		}
	}
	return cases, nil
}

func loadCase(dir string, kind Kind) (Case, error) {
	id := filepath.Base(dir)
	fail := func(format string, args ...any) (Case, error) {
		return Case{}, fmt.Errorf("eval: %s/%s: %s", kind, id, fmt.Sprintf(format, args...))
	}
	if !caseIDRe.MatchString(id) {
		return fail("case id must match %s", caseIDRe)
	}
	if st, err := os.Stat(filepath.Join(dir, "report.md")); err != nil || !st.Mode().IsRegular() {
		return fail("missing report.md")
	}
	f, err := os.Open(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fail("%v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 64<<10))
	dec.DisallowUnknownFields()
	var m Meta
	if err := dec.Decode(&m); err != nil {
		return fail("meta.json: %v", err)
	}

	if err := report.ValidateRepo(m.Repo); err != nil {
		return fail("%v", err)
	}
	if !m.Expected.Valid() {
		return fail("unknown expected_outcome %q", m.Expected)
	}
	switch {
	case m.Ref == "" && m.Expected != report.OutcomeNeedsInfo:
		return fail("empty ref is only allowed when expected_outcome is NEEDS_INFO")
	case m.Ref != "" && !report.IsFullSHA(m.Ref):
		return fail("ref %q must be a full 40-hex commit SHA", m.Ref)
	}
	switch kind {
	case KindReal:
		if !strings.HasPrefix(m.Source, "GHSA-") && !strings.HasPrefix(m.Source, "GO-") {
			return fail("real case source must start with GHSA- or GO-, got %q", m.Source)
		}
		if m.Expected == report.OutcomeGroundingFailed {
			return fail("a real report must never expect GROUNDING_FAILED")
		}
	case KindFabricated:
		if m.Source != "fabricated" {
			return fail(`fabricated case source must be "fabricated", got %q`, m.Source)
		}
	}
	return Case{ID: id, Kind: kind, Dir: dir, Meta: m}, nil
}

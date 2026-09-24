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
	// ExpectedDuplicateOf is another case's ID this case is a
	// near-duplicate of: Scoreboard.DuplicateTop1Accuracy checks that
	// the LIKELY_DUPLICATE verdict's top match actually points at that
	// case's report, not merely that the outcome came out right.
	ExpectedDuplicateOf string `json:"expected_duplicate_of,omitempty"`
	Notes               string `json:"notes,omitempty"`
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
	ids := map[string]bool{}
	for _, c := range cases {
		ids[c.ID] = true
	}
	for _, c := range cases {
		if c.Meta.ExpectedDuplicateOf != "" && !ids[c.Meta.ExpectedDuplicateOf] {
			return nil, fmt.Errorf("eval: %s/%s: expected_duplicate_of %q does not match any loaded case id", c.Kind, c.ID, c.Meta.ExpectedDuplicateOf)
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
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fail("meta.json: trailing data after the JSON object")
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
	if m.ExpectedDuplicateOf != "" {
		if !caseIDRe.MatchString(m.ExpectedDuplicateOf) {
			return fail("expected_duplicate_of must be a valid case id, got %q", m.ExpectedDuplicateOf)
		}
		if m.Expected != report.OutcomeLikelyDuplicate {
			return fail("expected_duplicate_of is only meaningful when expected_outcome is LIKELY_DUPLICATE")
		}
	}
	return Case{ID: id, Kind: kind, Dir: dir, Meta: m}, nil
}

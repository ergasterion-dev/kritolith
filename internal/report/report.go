// Package report holds Kritolith's core model: reports, claims and verdicts.
package report

import (
	"fmt"
	"time"
)

// Source says how a report reached Kritolith.
type Source string

const (
	SourceGitHubPVR Source = "github_pvr"
	SourceEML       Source = "eml"
	SourceFile      Source = "file"
)

// ClaimKind is the kind of concrete, checkable statement a report makes.
type ClaimKind string

const (
	ClaimFile      ClaimKind = "file"
	ClaimFunction  ClaimKind = "function"
	ClaimLine      ClaimKind = "line"
	ClaimVersion   ClaimKind = "version"
	ClaimVulnClass ClaimKind = "vuln_class"
	ClaimSink      ClaimKind = "sink"
)

// Tri is a three-valued verification result.
type Tri string

const (
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
	TriUnknown Tri = "unknown"
)

// Outcome is the verdict for a report. v1 has exactly these seven.
type Outcome string

const (
	OutcomeReproduced            Outcome = "REPRODUCED"
	OutcomeReproducedFixedAtHead Outcome = "REPRODUCED_FIXED_AT_HEAD"
	OutcomeNotReproduced         Outcome = "NOT_REPRODUCED"
	OutcomeGroundingFailed       Outcome = "GROUNDING_FAILED"
	OutcomeLikelyDuplicate       Outcome = "LIKELY_DUPLICATE"
	OutcomeNeedsInfo             Outcome = "NEEDS_INFO"
	OutcomeInconclusive          Outcome = "INCONCLUSIVE"
)

// Outcomes returns every valid outcome.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeReproduced,
		OutcomeReproducedFixedAtHead,
		OutcomeNotReproduced,
		OutcomeGroundingFailed,
		OutcomeLikelyDuplicate,
		OutcomeNeedsInfo,
		OutcomeInconclusive,
	}
}

// Valid reports whether o is one of the seven v1 outcomes.
func (o Outcome) Valid() bool {
	for _, v := range Outcomes() {
		if o == v {
			return true
		}
	}
	return false
}

// ParseOutcome converts s to an Outcome, rejecting anything not in Outcomes.
func ParseOutcome(s string) (Outcome, error) {
	o := Outcome(s)
	if !o.Valid() {
		return "", fmt.Errorf("report: unknown outcome %q", s)
	}
	return o, nil
}

// Artifact is one PoC file attached to a report. Content is hostile.
type Artifact struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// Report is a normalized incoming report. Everything except ID and
// ReceivedAt comes from the reporter and is untrusted.
type Report struct {
	ID         string     `json:"id"`
	Source     Source     `json:"source"`
	SourceRef  string     `json:"source_ref"`
	Repo       string     `json:"repo"`
	ClaimedRef string     `json:"claimed_ref"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	PoC        []Artifact `json:"poc"`
	ReceivedAt time.Time  `json:"received_at"`
}

// Claim is one checkable statement extracted from a report.
type Claim struct {
	Kind     ClaimKind `json:"kind"`
	Value    string    `json:"value"`
	Source   string    `json:"source"` // "deterministic" or "llm:<model>"
	Verified Tri       `json:"verified"`
	Evidence string    `json:"evidence"`
}

// DupMatch is a possible duplicate of the report.
type DupMatch struct {
	ReportID   string  `json:"report_id,omitempty"`
	AdvisoryID string  `json:"advisory_id,omitempty"`
	Score      float64 `json:"score"`
}

// ReproResult is the outcome of running the PoC at one ref.
type ReproResult struct {
	Ref        string `json:"ref"`
	Reproduced bool   `json:"reproduced"`
	Signal     string `json:"signal"`
}

// Verdict is Kritolith's evidence summary for one report.
type Verdict struct {
	ReportID   string       `json:"report_id"`
	Outcome    Outcome      `json:"outcome"`
	Claims     []Claim      `json:"claims"`
	Duplicates []DupMatch   `json:"duplicates"`
	Repro      *ReproResult `json:"repro"`
	Notes      []string     `json:"notes"`       // why the outcome was chosen
	DraftReply string       `json:"draft_reply"` // LLM-drafted, clearly marked as draft
	Signature  []byte       `json:"signature"`
	SignedAt   time.Time    `json:"signed_at"`
}

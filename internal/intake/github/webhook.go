package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// MaxWebhookBytes caps a webhook body. GitHub's own limit is 25 MiB;
// a repository_advisory event is a few kilobytes.
const MaxWebhookBytes = 5 << 20

// VerifyWebhook reports whether signature, the X-Hub-Signature-256
// header, is the HMAC-SHA256 of body under secret. It must be called
// on the raw body before anything in it is parsed or trusted: the
// endpoint is on the network, and the signature is the only thing
// that says a delivery came from GitHub. An empty secret never
// verifies.
func VerifyWebhook(secret, body []byte, signature string) bool {
	if len(secret) == 0 {
		return false
	}
	hexSig, ok := strings.CutPrefix(signature, "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// NewReport is a private vulnerability report announced by a webhook.
type NewReport struct {
	Repo   string // owner/name
	GHSAID string // canonical form
}

// ErrNotANewReport means a delivery was understood and is not the
// announcement of a new private report: another event, or another
// action on an advisory. It is not a failure.
var ErrNotANewReport = errors.New("not a new private vulnerability report")

// ParseWebhook reads a verified delivery. It returns the report it
// announces if event is "repository_advisory" with action "reported",
// which is what GitHub sends when someone files a private report.
// Only the repository's name and the advisory's ID are taken from the
// payload; the report itself is fetched from the API afterwards, so
// nothing else in a webhook body is ever acted on.
func ParseWebhook(event string, body []byte) (NewReport, error) {
	if event != "repository_advisory" {
		return NewReport{}, ErrNotANewReport
	}
	var p struct {
		Action     string `json:"action"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		RepositoryAdvisory struct {
			GHSAID string `json:"ghsa_id"`
		} `json:"repository_advisory"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return NewReport{}, errors.New("webhook body is not JSON")
	}
	if p.Action != "reported" {
		return NewReport{}, ErrNotANewReport
	}
	if err := report.ValidateRepo(p.Repository.FullName); err != nil {
		return NewReport{}, fmt.Errorf("webhook names an invalid repository")
	}
	id, err := normalizeGHSAID(p.RepositoryAdvisory.GHSAID)
	if err != nil {
		return NewReport{}, fmt.Errorf("webhook names an invalid advisory ID")
	}
	return NewReport{Repo: p.Repository.FullName, GHSAID: id}, nil
}

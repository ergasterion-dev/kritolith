// Package github turns a GitHub repository security advisory, which
// is how a private vulnerability report arrives, into a report.Report.
// It makes one authenticated GET to GitHub's REST API. Everything in
// the advisory was written by the reporter and is hostile input.
package github

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	// DefaultAPIURL is GitHub's public REST API. GitHub Enterprise
	// Server uses https://<host>/api/v3.
	DefaultAPIURL = "https://api.github.com"

	apiVersion       = "2022-11-28"
	requestTimeout   = 30 * time.Second
	maxResponseBytes = 4 << 20 // the API caps a description at 65535 characters; this is far above any real answer
	maxBodyBytes     = 1 << 20 // same cap as a report file
	maxTitleRunes    = 200
	maxListed        = 50 // affected packages and functions copied into the body
)

// ghsaRe is GitHub's advisory ID format: three groups of four
// characters from a fixed alphabet. Checking it keeps the ID safe to
// place in a URL path.
var ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

// rangeVersionRe finds the versions in an advisory's affected range
// that are themselves affected ("<= 1.2.3", "= 1.2.3", or a range that
// is just "1.2.3"). A version after a bare "<" is the first fixed one
// and is deliberately not matched.
var rangeVersionRe = regexp.MustCompile(`(?:^|,|<=|(?:^|[^<>!])=)\s*v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?)`)

// Options describes one advisory to load.
type Options struct {
	Repo   string // owner/name, required
	GHSAID string // GHSA-xxxx-xxxx-xxxx, required
	Ref    string // commit SHA or tag, if the operator knows it; advisories carry none
	Token  string // GitHub token that can read the repository's advisories, required
	APIURL string // empty means DefaultAPIURL

	HTTPClient *http.Client // nil means a client with a timeout that refuses redirects
	Now        func() time.Time
	Rand       io.Reader
}

type advisory struct {
	GHSAID          string  `json:"ghsa_id"`
	Summary         string  `json:"summary"`
	Description     *string `json:"description"`
	State           string  `json:"state"`
	Vulnerabilities []struct {
		Package *struct {
			Ecosystem string  `json:"ecosystem"`
			Name      *string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange *string  `json:"vulnerable_version_range"`
		VulnerableFunctions    []string `json:"vulnerable_functions"`
	} `json:"vulnerabilities"`
}

// Load fetches the advisory and returns it as a report.
func Load(ctx context.Context, opts Options) (report.Report, error) {
	if err := report.ValidateRepo(opts.Repo); err != nil {
		return report.Report{}, fmt.Errorf("intake/github: %w", err)
	}
	id, err := normalizeGHSAID(opts.GHSAID)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/github: %w", err)
	}
	if opts.Ref != "" {
		if err := report.ValidateRef(opts.Ref); err != nil {
			return report.Report{}, fmt.Errorf("intake/github: %w", err)
		}
	}
	if opts.Token == "" {
		return report.Report{}, errors.New("intake/github: no GitHub token")
	}
	if strings.ContainsAny(opts.Token, " \t\r\n") {
		return report.Report{}, errors.New("intake/github: the GitHub token contains whitespace")
	}
	base := opts.APIURL
	if base == "" {
		base = DefaultAPIURL
	}
	if err := validateAPIURL(base); err != nil {
		return report.Report{}, fmt.Errorf("intake/github: %w", err)
	}

	adv, err := fetch(ctx, opts.HTTPClient, strings.TrimRight(base, "/"), opts.Repo, id, opts.Token)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/github: %s in %s: %w", id, opts.Repo, err)
	}
	if got, err := normalizeGHSAID(adv.GHSAID); err != nil || got != id {
		return report.Report{}, fmt.Errorf("intake/github: asked for %s but the answer is for %q", id, report.Printable(adv.GHSAID))
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	rnd := io.Reader(rand.Reader)
	if opts.Rand != nil {
		rnd = opts.Rand
	}
	received := now().UTC()
	reportID, err := report.NewID(received, rnd)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/github: %w", err)
	}
	return report.Report{
		ID:         reportID,
		Source:     report.SourceGitHubPVR,
		SourceRef:  id,
		Repo:       opts.Repo,
		ClaimedRef: opts.Ref,
		Title:      title(adv.Summary),
		Body:       body(adv),
		ReceivedAt: received,
	}, nil
}

// normalizeGHSAID accepts any letter case and returns the canonical
// form: "GHSA" upper case, the rest lower case.
func normalizeGHSAID(s string) (string, error) {
	if len(s) < 4 {
		return "", fmt.Errorf("invalid advisory ID %q: want GHSA-xxxx-xxxx-xxxx", s)
	}
	id := strings.ToUpper(s[:4]) + strings.ToLower(s[4:])
	if !ghsaRe.MatchString(id) {
		return "", fmt.Errorf("invalid advisory ID %q: want GHSA-xxxx-xxxx-xxxx", s)
	}
	return id, nil
}

// validateAPIURL requires https, because the request carries the
// token. Plain http is allowed only to a loopback address, which is
// what a test server or a local tunnel uses.
func validateAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid GitHub API URL %q", raw)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid GitHub API URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("GitHub API URL %q must use https: the request carries your token", raw)
}

func fetch(ctx context.Context, client *http.Client, base, repo, id, token string) (advisory, error) {
	if client == nil {
		client = &http.Client{
			Timeout: requestTimeout,
			// A redirect could carry the token, or the embargoed
			// answer's request, to another host. The API has no reason
			// to send one.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/repos/"+repo+"/security-advisories/"+id, nil)
	if err != nil {
		return advisory{}, errors.New("could not build the request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "kritolith")

	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error names the URL and the cause, never a header.
		return advisory{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return advisory{}, statusError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return advisory{}, fmt.Errorf("reading the answer: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return advisory{}, fmt.Errorf("the answer is larger than %d bytes", maxResponseBytes)
	}
	var adv advisory
	// Unknown fields are expected: the API grows, and only a few
	// fields are used.
	if err := json.Unmarshal(raw, &adv); err != nil {
		return advisory{}, errors.New("the answer is not the JSON the advisories API documents")
	}
	return adv, nil
}

// statusError explains a non-200 answer in terms the operator can act
// on. It never echoes the response body: for a private advisory even
// an error page is not something to print.
func statusError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("GitHub rejected the token (401)")
	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" {
			return fmt.Errorf("GitHub rate limit reached (%d); try again later", resp.StatusCode)
		}
		return errors.New("the token may not read this repository's security advisories (403); a classic token needs the repo or repository_advisories scope, a fine-grained token needs read access to \"Repository security advisories\"")
	case http.StatusNotFound:
		return errors.New("not found (404): the advisory does not exist, or the token cannot see it; reports that are not published are visible only to repository administrators, security managers and collaborators on the advisory")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("GitHub answered with a redirect (%d), which is refused", resp.StatusCode)
	}
	return fmt.Errorf("GitHub answered %d", resp.StatusCode)
}

// title is the advisory summary as one printable line.
func title(summary string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(summary), "\n")
	r := []rune(report.Printable(strings.TrimSpace(line)))
	if len(r) > maxTitleRunes {
		r = r[:maxTitleRunes]
	}
	return string(r)
}

// body lays the advisory out as report text: the summary, the
// description, then the structured "affected" fields as prose, so
// claim extraction reads all of it the same way it reads a report
// file. The reporter fills in those fields too, so they are claims,
// not facts.
func body(adv advisory) string {
	var b strings.Builder
	if s := strings.TrimSpace(adv.Summary); s != "" {
		b.WriteString("# " + strings.ReplaceAll(s, "\n", " ") + "\n\n")
	}
	if adv.Description != nil {
		b.WriteString(strings.ReplaceAll(*adv.Description, "\r\n", "\n"))
		b.WriteString("\n")
	}

	var affected []string
	seen := map[string]bool{}
	add := func(line string) {
		if len(affected) < maxListed && !seen[line] {
			seen[line] = true
			affected = append(affected, line)
		}
	}
	for _, v := range adv.Vulnerabilities {
		if v.Package != nil && v.Package.Name != nil && strings.TrimSpace(*v.Package.Name) != "" {
			add("- package " + oneLine(*v.Package.Name))
		}
		if v.VulnerableVersionRange != nil && strings.TrimSpace(*v.VulnerableVersionRange) != "" {
			add("- affected versions: " + oneLine(*v.VulnerableVersionRange))
			for _, m := range rangeVersionRe.FindAllStringSubmatch(*v.VulnerableVersionRange, maxListed) {
				// Go release tags carry a "v" prefix; written this way
				// the version becomes a candidate ref when the report
				// names no commit.
				add("- affected release: v" + m[1])
			}
		}
		for _, fn := range v.VulnerableFunctions {
			if strings.TrimSpace(fn) != "" {
				add("- vulnerable function: " + oneLine(fn))
			}
		}
	}
	if len(affected) > 0 {
		b.WriteString("\n## Affected (as entered on the advisory)\n\n")
		b.WriteString(strings.Join(affected, "\n"))
		b.WriteString("\n")
	}

	out := strings.ToValidUTF8(b.String(), "�")
	if len(out) > maxBodyBytes {
		out = strings.ToValidUTF8(out[:maxBodyBytes], "")
	}
	return out
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

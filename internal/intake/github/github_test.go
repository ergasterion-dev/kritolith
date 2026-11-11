package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/extract/deterministic"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

const testID = "GHSA-mh63-6h87-95cp"

// advisoryJSON is trimmed from a real published advisory
// (golang-jwt/jwt, GHSA-mh63-6h87-95cp), with fields this package
// doesn't read left in to prove they are ignored.
const advisoryJSON = `{
  "ghsa_id": "GHSA-mh63-6h87-95cp",
  "cve_id": "CVE-2025-30204",
  "html_url": "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
  "summary": "Excessive memory allocation during header parsing",
  "description": "### Summary\r\n\r\nFunction ` + "`parse.ParseUnverified`" + ` in parser.go:138 splits its argument on periods.\r\n",
  "severity": "high",
  "state": "triage",
  "submission": {"accepted": false},
  "vulnerabilities": [
    {"package": {"ecosystem": "go", "name": "github.com/golang-jwt/jwt/v5"},
     "vulnerable_version_range": "<= 5.2.1", "patched_versions": "5.2.2",
     "vulnerable_functions": ["Parser.ParseUnverified"]},
    {"package": {"ecosystem": "go", "name": "github.com/golang-jwt/jwt/v4"},
     "vulnerable_version_range": ">= 4.0.0, < 4.5.2", "patched_versions": "4.5.2",
     "vulnerable_functions": null},
    {"package": null, "vulnerable_version_range": null, "vulnerable_functions": []}
  ],
  "cwe_ids": ["CWE-405"],
  "comments": 7
}`

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func opts(apiURL string) Options {
	return Options{
		Repo: "golang-jwt/jwt", GHSAID: testID, Token: "tok_secret", APIURL: apiURL,
		Now:  func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) },
		Rand: bytes.NewReader(make([]byte, 16)),
	}
}

func TestLoad(t *testing.T) {
	var got *http.Request
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(advisoryJSON))
	})
	o := opts(url)
	o.GHSAID = "ghsa-MH63-6H87-95CP" // any case is accepted
	o.Ref = "v5.2.1"
	r, err := Load(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	if got.Method != http.MethodGet || got.URL.Path != "/repos/golang-jwt/jwt/security-advisories/"+testID {
		t.Errorf("request = %s %s", got.Method, got.URL.Path)
	}
	if h := got.Header.Get("Authorization"); h != "Bearer tok_secret" {
		t.Errorf("Authorization = %q", h)
	}
	if got.Header.Get("Accept") != "application/vnd.github+json" || got.Header.Get("X-GitHub-Api-Version") == "" {
		t.Errorf("headers = %v", got.Header)
	}

	if r.Source != report.SourceGitHubPVR || r.SourceRef != testID || r.Repo != "golang-jwt/jwt" || r.ClaimedRef != "v5.2.1" {
		t.Errorf("report = %+v", r)
	}
	if r.ID == "" || r.ReceivedAt.IsZero() || len(r.PoC) != 0 {
		t.Errorf("report = %+v", r)
	}
	if r.Title != "Excessive memory allocation during header parsing" {
		t.Errorf("title = %q", r.Title)
	}
	for _, want := range []string{
		"# Excessive memory allocation during header parsing\n",
		"`parse.ParseUnverified` in parser.go:138",
		"- package github.com/golang-jwt/jwt/v5\n",
		"- affected versions: <= 5.2.1\n",
		"- affected release: v5.2.1\n",
		"- vulnerable function: Parser.ParseUnverified\n",
		"- affected versions: >= 4.0.0, < 4.5.2\n",
	} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("body missing %q:\n%s", want, r.Body)
		}
	}
	if strings.Contains(r.Body, "\r") {
		t.Error("body kept carriage returns")
	}
	// "< 4.5.2" names the first fixed release, and ">= 4.0.0" a lower
	// bound that says nothing about which tag to check; neither may
	// become a candidate ref.
	for _, bad := range []string{"v4.5.2", "v4.0.0", "v5.2.2"} {
		if strings.Contains(r.Body, bad) {
			t.Errorf("body offers %s as an affected release:\n%s", bad, r.Body)
		}
	}

	// The body must read as a report to the extractor.
	have := map[string]bool{}
	for _, c := range deterministic.Extract(r.Body) {
		have[string(c.Kind)+" "+c.Value] = true
	}
	for _, want := range []string{"function parse.ParseUnverified", "line parser.go:138", "version v5.2.1", "function Parser.ParseUnverified"} {
		if !have[want] {
			t.Errorf("extraction missed %q; got %v", want, have)
		}
	}
}

func TestLoadMinimalAdvisory(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ghsa_id": "` + testID + `", "summary": "", "description": null, "vulnerabilities": null}`))
	})
	r, err := Load(context.Background(), opts(url))
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "" || r.Body != "" || r.ClaimedRef != "" {
		t.Errorf("report = %+v", r)
	}
}

func TestLoadSanitizesAndBounds(t *testing.T) {
	huge := strings.Repeat("A", maxBodyBytes+500)
	adv := map[string]any{
		"ghsa_id":     testID,
		"summary":     "\x1b]0;pwned\x07 title \u202Edesrever\nsecond line " + strings.Repeat("x", 500),
		"description": huge,
		"vulnerabilities": []any{map[string]any{
			"package":                  map[string]any{"ecosystem": "go", "name": "evil\n## Reproduce\nname"},
			"vulnerable_version_range": "<= 1.0.0\n- affected release: v9.9.9",
			"vulnerable_functions":     []string{"a.B\nc.D"},
		}},
	}
	raw, err := json.Marshal(adv)
	if err != nil {
		t.Fatal(err)
	}
	url := serve(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) })
	r, err := Load(context.Background(), opts(url))
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != report.Printable(r.Title) || strings.Contains(r.Title, "second line") || len([]rune(r.Title)) > maxTitleRunes {
		t.Errorf("title = %q", r.Title)
	}
	if len(r.Body) > maxBodyBytes {
		t.Errorf("body is %d bytes; cap is %d", len(r.Body), maxBodyBytes)
	}

	// With a short description, the structured fields are present
	// and each stays on its own line: a field can't start a new
	// heading or list item.
	adv["description"] = "short"
	raw, _ = json.Marshal(adv)
	r, err = Load(context.Background(), opts(url))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- package evil ## Reproduce name\n",
		"- affected versions: <= 1.0.0 - affected release: v9.9.9\n",
		"- vulnerable function: a.B c.D\n",
	} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("body missing %q:\n%s", want, r.Body)
		}
	}
	if strings.Contains(r.Body, "\n## Reproduce") {
		t.Errorf("a field injected a heading:\n%s", r.Body)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	called := false
	url := serve(t, func(w http.ResponseWriter, r *http.Request) { called = true })
	for name, mut := range map[string]func(*Options){
		"repo":             func(o *Options) { o.Repo = "not a repo" },
		"id shape":         func(o *Options) { o.GHSAID = "GHSA-1234" },
		"id traversal":     func(o *Options) { o.GHSAID = "GHSA-mh63-6h87-95cp/../../x" },
		"id alphabet":      func(o *Options) { o.GHSAID = "GHSA-aaaa-bbbb-1111" },
		"id empty":         func(o *Options) { o.GHSAID = "" },
		"ref":              func(o *Options) { o.Ref = "--upload-pack=x" },
		"no token":         func(o *Options) { o.Token = "" },
		"token newline":    func(o *Options) { o.Token = "tok\r\nX-Evil: 1" },
		"http remote":      func(o *Options) { o.APIURL = "http://api.github.example" },
		"userinfo":         func(o *Options) { o.APIURL = "https://user:pw@api.github.com" },
		"query":            func(o *Options) { o.APIURL = "https://api.github.com?x=1" },
		"no host":          func(o *Options) { o.APIURL = "https://" },
		"other scheme":     func(o *Options) { o.APIURL = "file:///etc/passwd" },
		"unparseable url":  func(o *Options) { o.APIURL = "https://[::1" },
		"http localhost-y": func(o *Options) { o.APIURL = "http://localhost.evil.example" },
	} {
		o := opts(url)
		mut(&o)
		if _, err := Load(context.Background(), o); err == nil {
			t.Errorf("%s: want an error", name)
		} else if strings.Contains(err.Error(), "tok_secret") {
			t.Errorf("%s: error leaks the token: %v", name, err)
		}
	}
	if called {
		t.Error("a request was sent for invalid input")
	}
}

func TestLoadHTTPErrors(t *testing.T) {
	secretBody := `{"message": "embargoed-detail-marker"}`
	cases := []struct {
		name   string
		status int
		header map[string]string
		want   string
	}{
		{"unauthorized", 401, nil, "rejected the token"},
		{"forbidden", 403, nil, "Repository security advisories"},
		{"rate limited", 403, map[string]string{"X-RateLimit-Remaining": "0"}, "rate limit"},
		{"secondary rate limit", 429, map[string]string{"Retry-After": "60"}, "rate limit"},
		{"not found", 404, nil, "cannot see it"},
		{"redirect", 302, map[string]string{"Location": "https://evil.example/"}, "redirect"},
		{"server error", 500, nil, "answered 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := serve(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(secretBody))
			})
			_, err := Load(context.Background(), opts(url))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "embargoed-detail-marker") || strings.Contains(err.Error(), "tok_secret") {
				t.Fatalf("error leaks the response body or the token: %v", err)
			}
			if !strings.Contains(err.Error(), testID) || !strings.Contains(err.Error(), "golang-jwt/jwt") {
				t.Errorf("error doesn't say which advisory: %v", err)
			}
		})
	}
}

// A redirect must not be followed: the next request would carry the
// token to whatever host the answer names.
func TestLoadNeverFollowsRedirects(t *testing.T) {
	hit := false
	other := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = w.Write([]byte(advisoryJSON))
	})
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other+r.URL.Path, http.StatusTemporaryRedirect)
	})
	if _, err := Load(context.Background(), opts(url)); err == nil {
		t.Fatal("want an error for a redirect")
	}
	if hit {
		t.Fatal("the redirect was followed")
	}
}

func TestLoadRejectsBadAnswers(t *testing.T) {
	for name, payload := range map[string]string{
		"not json":       "<html>sign in</html>",
		"wrong advisory": `{"ghsa_id": "GHSA-2222-3333-4444", "summary": "s"}`,
		"no id":          `{"summary": "s"}`,
		"array":          `[]`,
		"too large":      `{"ghsa_id": "` + testID + `", "description": "` + strings.Repeat("a", maxResponseBytes) + `"}`,
	} {
		url := serve(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(payload)) })
		if _, err := Load(context.Background(), opts(url)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestLoadHonorsContext(t *testing.T) {
	release := make(chan struct{})
	url := serve(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Load(ctx, opts(url)); err == nil {
		t.Fatal("want an error when the context ends")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Load did not stop when the context ended")
	}
}

func TestRangeVersions(t *testing.T) {
	for in, want := range map[string]string{
		"<= 5.2.1":            "5.2.1",
		"= 1.2.3":             "1.2.3",
		"1.2.3":               "1.2.3",
		"v1.2.3":              "1.2.3",
		"<= 1.2.3-rc.1":       "1.2.3-rc.1",
		">= 1.0.0, <= 1.4.2":  "1.4.2",
		"< 4.5.2":             "",
		">= 4.0.0, < 4.5.2":   "",
		"> 1.0.0":             "",
		"!= 1.0.0":            "",
		"all versions":        "",
		"<= 1.2":              "",
		"<= 1.2.3, <= 2.0.1":  "1.2.3 2.0.1",
		"= 1.0.0, = 1.0.1":    "1.0.0 1.0.1",
		"1.0.0, 1.0.1":        "1.0.0 1.0.1",
		">=1.0.0,<=1.4.2":     "1.4.2",
		"<=1.2.3":             "1.2.3",
		"< 2.0.0, >= 1.5.0":   "",
		"<= 0.0.0-2021abcdef": "0.0.0-2021abcdef",
	} {
		var got []string
		for _, m := range rangeVersionRe.FindAllStringSubmatch(in, -1) {
			got = append(got, m[1])
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: got %q, want %q", in, strings.Join(got, " "), want)
		}
	}
}

func FuzzBody(f *testing.F) {
	f.Add("summary", "description", "pkg", "<= 1.2.3", "a.B")
	f.Add("\x1b[2J", "\xff\xfe", "\n## Reproduce\n", "<= 1.0.0\n- affected release: v9.9.9", "x\ny")
	f.Fuzz(func(t *testing.T, summary, description, pkg, rng, fn string) {
		var adv advisory
		raw, err := json.Marshal(map[string]any{
			"ghsa_id": testID, "summary": summary, "description": description,
			"vulnerabilities": []any{map[string]any{
				"package":                  map[string]any{"name": pkg},
				"vulnerable_version_range": rng,
				"vulnerable_functions":     []string{fn},
			}},
		})
		if err != nil || json.Unmarshal(raw, &adv) != nil {
			t.Skip()
		}
		b := body(adv)
		if len(b) > maxBodyBytes {
			t.Fatalf("body is %d bytes", len(b))
		}
		if tt := title(summary); tt != report.Printable(tt) || len([]rune(tt)) > maxTitleRunes {
			t.Fatalf("title %q", tt)
		}
		// Structured fields are single lines: none may add a line that
		// the reporter's field text did not get from the fixed layout.
		const heading = "\n## Affected (as entered on the advisory)\n\n"
		i := strings.LastIndex(b, heading)
		if i < 0 || strings.Contains(description, strings.TrimSpace(heading)) {
			return
		}
		affected := b[i+len(heading):]
		for _, line := range strings.Split(strings.TrimSuffix(affected, "\n"), "\n") {
			if !strings.HasPrefix(line, "- package ") && !strings.HasPrefix(line, "- affected versions: ") &&
				!strings.HasPrefix(line, "- affected release: v") && !strings.HasPrefix(line, "- vulnerable function: ") {
				t.Fatalf("unexpected line %q in the affected section:\n%s", line, b)
			}
		}
	})
}

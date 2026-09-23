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

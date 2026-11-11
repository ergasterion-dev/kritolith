# Large allocation when parsing a token made mostly of periods

golang-jwt/jwt v5.2.1: the function [`parse.ParseUnverified`](https://github.com/golang-jwt/jwt/blob/80dccb9209ebe7b503c067dc830fcbd4aa2e74eb/parser.go#L138-L139)
splits the token it is given on periods, with a call to [strings.Split](https://pkg.go.dev/strings#Split), before it checks anything else about the token.

The token comes from the `Authorization` header, so the caller controls it. A header of
`Bearer ` followed by a few megabytes of `.` characters makes the split allocate a slice
with one element per period: roughly sixteen bytes of bookkeeping for every byte sent.
The request is rejected afterwards, but the allocation has already happened, once per
request.

This is [CWE-405](https://cwe.mitre.org/data/definitions/405.html) (asymmetric resource
consumption). The package documentation is at pkg.go.dev/github.com/golang-jwt/jwt/v5 and
the function is also reachable through `ParseWithClaims` in `parser.go`.

Impact: a remote client can make a server that validates JWTs allocate large amounts of
memory with small requests.

Suggested fix: count the periods and refuse anything that does not have exactly two
before splitting.

# go-zero CORS allow-list can be bypassed by suffix

go-zero's CORS filter checks the request origin with a suffix comparison. `isOriginAllowed`
in `rest/internal/cors/handlers.go` returns true whenever the origin ends with an allowed
value, so configuring `safe.com` also lets `not-safe.com` through
and the response is shared cross-origin.

Impact: cross-origin data theft from services that rely on the go-zero CORS allow-list.

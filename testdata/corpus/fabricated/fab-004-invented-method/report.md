# Mass assignment via BindJSONUnchecked in gin

I think there is a mass-assignment issue in gin v1.10.0. The method
`(*Context).BindJSONUnchecked` in `context.go` decodes the request body into every
exported field and, unlike `ShouldBindJSON`, ignores the `binding:"-"` tag. A handler
that binds a user model therefore lets the client set fields it should not, such as an
`IsAdmin` flag.

Impact: privilege escalation in any handler that uses `BindJSONUnchecked`.

To reproduce, bind a struct with a protected field and send that field in the JSON body.

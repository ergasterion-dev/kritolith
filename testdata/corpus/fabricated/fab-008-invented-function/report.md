# Out-of-bounds read in google/uuid Parse for braced input

google/uuid v1.6.0 looks like it can panic in `Parse` (in `uuid.go`). For `{...}` input
`Parse` calls `parseBracedUnsafe`, which reads a fixed offset before checking the length,
so a short braced string reads past the end of the buffer.

Impact: a crash in any service that parses UUID strings from untrusted input.

To reproduce, call `uuid.Parse` with a `{` followed by fewer than the expected number of
characters.

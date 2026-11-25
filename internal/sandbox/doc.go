// Package sandbox reproduces a report's proof of concept in an
// isolated, network-less container and turns the outcome into
// evidence for the verdict. Everything it is handed (PoC files, source
// trees, go.mod) is hostile input: nothing here executes it on the
// host, and Go is only ever parsed with go/parser, never built or run
// outside the sandbox. A sandbox failure of any kind is inconclusive,
// never a rejection of the report.
package sandbox

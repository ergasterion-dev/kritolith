# gomarkdown hangs on a short definition-list input

gomarkdown/markdown can get stuck in an endless loop. With the definition-list extension
enabled (it is part of the common extension set) `(*Parser).paragraph` in `parser/block.go`
returns the same offset it started from when the inner list parse consumes nothing, so the
block loop never advances and the parser spins on the same bytes.

Impact: a small markdown snippet pins a CPU forever in any service that renders
user-supplied markdown.

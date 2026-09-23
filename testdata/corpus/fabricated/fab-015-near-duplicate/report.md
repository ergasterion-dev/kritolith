# yaml.v3 crashes on a malformed short document

Reporting what looks like a crash bug in gopkg.in/yaml.v3. Feeding `Unmarshal` a tiny
malformed document that ends mid-UTF-8 makes the decoder blow up instead of returning an
error. The problem is in `(*parser).peek` in `decode.go`: it only looks at the boolean
returned by the underlying parser and misses the error flag, so it forwards a bogus event
and the decoder panics.

Impact: a few bytes of bad YAML can take down anything that decodes untrusted input with
yaml.v3.

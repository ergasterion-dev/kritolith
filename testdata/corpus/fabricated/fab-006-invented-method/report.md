# zstd DecodeAll ignores the configured memory limit

In klauspost/compress v1.17.9, `(*Decoder).DecodeAll` in `zstd/decoder.go` routes frames
with an unknown content size through `(*Decoder).decodeAllUnbounded`, which grows the
output buffer without checking `WithDecoderMaxMemory`. A small frame can drive a very
large allocation.

Impact: memory exhaustion when decompressing untrusted zstd data even though a limit was
set with `WithDecoderMaxMemory`.

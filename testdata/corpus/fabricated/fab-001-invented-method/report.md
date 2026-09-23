# Out-of-bounds read in http2 CONTINUATION handling

Hi, I found a memory safety issue in golang.org/x/net/http2 (tested at v0.38.0).

The method `(*Framer).ReadContinuationUnsafe` in `http2/frame.go` (around line 1302)
copies the header block fragment from a CONTINUATION frame without checking the
frame length against the remaining buffer. A peer can send a CONTINUATION frame
with a declared length larger than the payload and read adjacent heap memory.

Impact: remote information disclosure from any Go HTTP/2 server.

Steps to reproduce:

```go
fr := http2.NewFramer(w, r)
fr.ReadContinuationUnsafe(maliciousFrameHeader)
```

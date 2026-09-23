# Unbounded decompression in gorilla/websocket permessage-deflate

gorilla/websocket v1.5.3 has a decompression bomb in `compression.go`. The method
`(*Conn).readCompressedFrameInto` inflates the whole compressed message into a
single buffer with no size cap, ignoring `SetReadLimit`.

A 1 MB compressed frame can inflate to several GB and crash the server (OOM).

PoC:

```go
conn.EnableWriteCompression(true)
conn.WriteMessage(websocket.BinaryMessage, bomb)
```

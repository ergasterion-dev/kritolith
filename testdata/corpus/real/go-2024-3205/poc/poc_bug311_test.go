package parser

import (
	"testing"
	"time"
)

// Input from the fix commit's parser_test.go (TestBug311).
// Vulnerable: Parse loops forever in Parser.paragraph. Fixed: it returns.
func TestPoCBug311InfiniteLoop(t *testing.T) {
	str := "~~~~\xb4~\x94~\x94~\xd1\r\r:\xb4\x94\x94~\x9f~\xb4~\x94~\x94\x94"
	done := make(chan struct{})
	go func() {
		New().Parse([]byte(str))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Parse did not return within 5s (infinite loop)")
	}
}

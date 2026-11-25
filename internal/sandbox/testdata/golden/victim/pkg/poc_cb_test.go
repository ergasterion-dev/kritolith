package pkg

import "testing"

func TestCallback(t *testing.T) {
	Walk(func() {
		var m map[string]int
		m["x"] = 1
	})
}

package pkg

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestPanicClaimed(t *testing.T)  { (&Parser{}).Parse([]byte("a")) }
func TestNilDeref(t *testing.T)      { Deref(nil) }
func TestStackOverflow(t *testing.T) { Recurse(0) }
func TestMapWrite(t *testing.T)      { MapWrite(map[int]int{}) }
func TestRace(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go Count(&wg)
	}
	wg.Wait()
}
func TestAssert(t *testing.T) {
	if Clean(20) != 20 {
		t.Fatalf("Clean(20) = %d, want 20", Clean(20))
	}
}
func TestAssertNoClaim(t *testing.T) {
	if Other() != 8 {
		t.Fatal("Other() != 8")
	}
}
func TestPanicPoC(t *testing.T) {
	var s []int
	_ = s[5]
}
func TestPanicStdlib(t *testing.T) {
	time.NewTicker(0)
}
func TestExit(t *testing.T)    { os.Exit(1) }
func TestHang(t *testing.T)    { select {} }
func TestGeneric(t *testing.T) { Generic[int](nil) }
func TestClosure(t *testing.T) {
	f := func() { Deref(nil) }
	f()
}
func TestPass(t *testing.T) { _ = Clean(1) }

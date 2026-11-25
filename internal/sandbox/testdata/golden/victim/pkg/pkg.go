package pkg

import "sync"

type Parser struct{ m map[int]int }

// Parse panics on short input (index out of range).
func (p *Parser) Parse(b []byte) byte {
	return b[3]
}

// Deref dereferences a nil pointer.
func Deref(p *Parser) int {
	return len(p.m)
}

// Recurse never terminates.
func Recurse(n int) int {
	return Recurse(n+1) + 1
}

// Count increments a shared counter without a lock.
var counter int

func Count(wg *sync.WaitGroup) {
	defer wg.Done()
	counter++
}

// MapWrite writes a shared map from many goroutines.
func MapWrite(m map[int]int) {
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100000; j++ {
				m[j] = j
			}
		}()
	}
	wg.Wait()
}

// Clean returns a value and is covered by tests.
func Clean(x int) int {
	if x > 10 {
		return x * 2
	}
	return x
}

// Generic panics on nil.
func Generic[T any](v *T) T {
	return *v
}

func Other() int { return 7 }

// Walk calls f.
func Walk(f func()) { f() }

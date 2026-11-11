GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-quick vet fmt fmt-check eval ci clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/kritolith ./cmd/kritolith

# The full test run, including the corpus test that clones about twenty
# repositories. A plain `go test ./...` skips that one test.
test:
	KRITOLITH_CORPUS_TEST=1 $(GO) test -race -timeout 20m ./...

# Everything except the corpus test: about a minute.
test-quick:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^testdata/')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

eval:
	$(GO) run ./cmd/kritolith eval --corpus testdata/corpus

ci: fmt-check vet test build eval

clean:
	rm -rf bin

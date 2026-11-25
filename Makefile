GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-quick vet fmt fmt-check eval ci clean sandbox-rootfs sandbox-test

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

# --- Sandbox integration tests (docs/sandbox.md) -------------------------
# Pinned versions: the Go image doubles as the sandbox rootfs; the gVisor
# release is the one the runsc flags were checked against.
SANDBOX_GO_IMAGE      ?= golang:1.26.0-bookworm
GVISOR_RELEASE        ?= 20261102.0
SANDBOX_ROOTFS_VOLUME ?= kritolith-sandbox-rootfs
SANDBOX_CGROUPS       ?=
SANDBOX_INTERNET      ?=

# Exports $(SANDBOX_GO_IMAGE) into the docker volume
# $(SANDBOX_ROOTFS_VOLUME) (unprivileged), then checks go and gcc in it.
# `docker volume rm $(SANDBOX_ROOTFS_VOLUME)` before re-running to rebuild.
sandbox-rootfs:
	docker volume create $(SANDBOX_ROOTFS_VOLUME) >/dev/null
	cid=$$(docker create $(SANDBOX_GO_IMAGE)) && \
	  docker export "$$cid" | docker run --rm -i --network=none -v $(SANDBOX_ROOTFS_VOLUME):/rootfs \
	    $(SANDBOX_GO_IMAGE) tar -x --numeric-owner -C /rootfs; \
	  status=$$?; docker rm "$$cid" >/dev/null; exit $$status
	docker run --rm --network=none -v $(SANDBOX_ROOTFS_VOLUME):/rootfs:ro $(SANDBOX_GO_IMAGE) \
	  sh -euc 'chroot /rootfs /usr/local/go/bin/go version; chroot /rootfs /usr/bin/gcc --version | head -n 1'

# Runs `go test -tags sandbox ./internal/sandbox` against a real runsc.
# PRIVILEGED container: runsc needs it to create its namespaces and gofer
# inside Docker. This is for the owner to run, by hand. The repository and
# the rootfs are mounted read-only; the host Docker socket is not mounted.
# runsc is installed inside from the gVisor release with its SHA-512
# checked (steps from https://gvisor.dev/docs/user_guide/install/).
# Cgroups are ignored inside, so --memory/--pids-limit bound the hostile
# fixtures instead.
sandbox-test:
	@echo "sandbox-test: starting a PRIVILEGED container (needed for nested runsc); see docs/sandbox.md"
	docker run --rm --privileged --memory=8g --pids-limit=8192 \
	  -v "$(CURDIR):/repo:ro" \
	  -v $(SANDBOX_ROOTFS_VOLUME):/rootfs:ro \
	  -e KRITOLITH_SANDBOX_ROOTFS=/rootfs \
	  -e KRITOLITH_SANDBOX_CGROUPS=$(SANDBOX_CGROUPS) \
	  -e KRITOLITH_SANDBOX_INTERNET=$(SANDBOX_INTERNET) \
	  -e GVISOR_RELEASE=$(GVISOR_RELEASE) \
	  -e GOFLAGS=-buildvcs=false \
	  $(SANDBOX_GO_IMAGE) sh -euc '\
	    apt-get update -qq && apt-get install -y -qq --no-install-recommends zstd >/dev/null; \
	    ARCH=$$(uname -m); \
	    URL=https://storage.googleapis.com/gvisor/releases/release/$${GVISOR_RELEASE}/$${ARCH}; \
	    mkdir -p /tmp/gvisor && cd /tmp/gvisor; \
	    wget -q $${URL}/gvisor.tar.zstd $${URL}/gvisor.tar.zstd.sha512; \
	    sha512sum -c gvisor.tar.zstd.sha512; \
	    tar --zstd -xf gvisor.tar.zstd -C /usr/local/bin; \
	    rm -f gvisor.tar.zstd gvisor.tar.zstd.sha512; \
	    runsc --version; \
	    cd /repo; \
	    go test -tags sandbox -count=1 -v -timeout 90m ./internal/sandbox'

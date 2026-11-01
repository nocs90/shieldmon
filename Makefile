GO       ?= go
BIN      := bin/shieldmon
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/nocs90/shieldmon/internal/cli.Version=$(VERSION)

.PHONY: all build image test test-unit test-race test-integration fuzz cover lint golangci fmt fmt-check vet tidy-check vuln clean

all: lint test-unit build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/shieldmon

test: test-unit

# Container image for this host's platform (docs/adr/0012-container-image.md); CI builds
# linux/amd64 and linux/arm64 and checks them with scripts/check-image.py.
IMAGE ?= shieldmon:dev
image:
	docker buildx build --build-arg VERSION=$(VERSION) --tag $(IMAGE) --load .

test-unit:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Real syft/grype/trivy against a pinned image digest. Needs network.
test-integration:
	$(GO) test -tags integration -run 'TestRealScanners|TestHostile' -count=1 -timeout 30m ./internal/engine

FUZZTIME ?= 20s
# Minimizing each new interesting input takes up to 60s by default: with realistic seeds
# (scanner output, SBOMs, VEX documents) that used the whole FUZZTIME, leaving almost no
# executions. A bounded number of minimization runs keeps throughput (and still shrinks
# crashers).
FUZZMINIMIZE ?= 100x
FUZZ_TARGETS := \
	FuzzParseGrype:./internal/scanner \
	FuzzParseTrivy:./internal/scanner \
	FuzzCanonicalPURL:./internal/normalize \
	FuzzCanonicalVulnID:./internal/normalize \
	FuzzString:./internal/redact \
	FuzzParseReference:./internal/oci \
	FuzzParseInventory:./internal/runtimectx \
	FuzzBaseAnnotations:./internal/oci \
	FuzzParse:./internal/vex \
	FuzzParseCycloneDX:./internal/sbom \
	FuzzParseKEV:./internal/enrich

# Parsers of hostile input: run every fuzz target for FUZZTIME each.
fuzz:
	@for t in $(FUZZ_TARGETS); do \
		name=$${t%%:*}; pkg=$${t#*:}; \
		echo "fuzz $$name ($$pkg, $(FUZZTIME))"; \
		$(GO) test -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINIMIZE) $$pkg || exit 1; \
	done

# Coverage gate: the floor only goes up (raise COVER_MIN as coverage grows). Statements run by
# any test count (-coverpkg): the end-to-end scenarios of internal/engine exercise store and
# report code that per-package numbers would miss.
COVER_MIN ?= 70
cover:
	$(GO) test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	echo "total coverage: $$total% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { exit (t+0 < m+0) }' || { echo "coverage below $(COVER_MIN)%"; exit 1; }

GOFILES = $$(find . -name '*.go' -not -path './vendor/*' -not -path './.git/*')

fmt:
	@gofmt -w $(GOFILES)

fmt-check:
	@out=$$(gofmt -l $(GOFILES)); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./...

golangci:
	@if command -v golangci-lint >/dev/null; then golangci-lint run ./...; \
	else echo "golangci-lint not installed: skipped (CI runs it)"; fi

lint: fmt-check vet golangci

tidy-check:
	$(GO) mod tidy -diff

# Known vulnerabilities in our own dependencies (needs network).
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

clean:
	rm -rf bin dist

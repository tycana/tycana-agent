# Developer entry points. CI runs the same targets; see .github/workflows/ci.yml.
GO        ?= go
BIN       := bin
# systemd-analyze exposure threshold on systemd's 0-100 scale (displayed score x10). 11 at M0; fail above 15.
SECURITY_THRESHOLD ?= 15

.PHONY: all build test vet lint nowrite security-score reproducible check snapshot clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o $(BIN)/ ./cmd/...

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

# ADR 0017: no host-mutating calls outside internal/state and internal/hostexec.
nowrite:
	$(GO) run ./tools/nowrite

# ADR 0009: the unit must stay hardened. Fails if the exposure score rises above the threshold.
security-score:
	systemd-analyze security --offline=true --no-pager --threshold=$(SECURITY_THRESHOLD) packaging/systemd/tycanad.service

# ADR 0012: two builds from two checkouts must be byte-identical.
reproducible:
	./scripts/reproducible.sh

check: vet nowrite test build security-score reproducible

snapshot:
	goreleaser release --snapshot --clean --skip=sign,sbom,publish

clean:
	rm -rf $(BIN) dist

PYTHON ?= python3
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

.PHONY: fmt lint test test-integration build-hands run
.PHONY: build-dns-enum test-dns-enum clean-dns-enum

fmt:
	@echo "No formatter configured."

lint:
	$(PYTHON) -m compileall brain

test:
	$(PYTHON) -m pytest brain/tests
	cd hands && go test ./...

test-integration:
	@echo "Integration tests are opt-in and not configured."

build-hands:
	@mkdir -p hands/bin
	cd hands && go build -ldflags "-X main.toolVersion=$(VERSION)" -o ../hands/bin/probe ./cmd/probe
	cd hands && go build -ldflags "-X main.toolVersion=$(VERSION)" -o ../hands/bin/http_verify ./cmd/http_verify
	cd hands && go build -ldflags "-X main.toolVersion=$(VERSION)" -o ../hands/bin/dns_enum ./cmd/dns_enum

build-dns-enum:
	@mkdir -p hands/bin
	cd hands && go build -ldflags "-X main.toolVersion=$(VERSION)" -o ../hands/bin/dns_enum ./cmd/dns_enum

test-dns-enum:
	cd hands/cmd/dns_enum && go test -v

clean-dns-enum:
	rm -f hands/bin/dns_enum

run:
	$(PYTHON) -m brain.cli.casm run --scope scopes/scope.yaml

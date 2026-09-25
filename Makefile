.PHONY: vendor
vendor: vendor/modules.txt

vendor/modules.txt: go.mod
	go mod vendor

.PHONY: build
build: cvetool

VERSION ?= $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)
cvetool: vendor
	go build -ldflags "-X main.Version=${VERSION}" ./cmd/...

.PHONY: clean
clean:
	rm -f cvetool
	rm -rf vendor

.PHONY: e2e e2e-update
e2e: cvetool
	bash tests/e2e.sh

e2e-update: cvetool
	bash tests/e2e-update.sh

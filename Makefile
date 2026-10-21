GO_VERSION := $(shell awk '$$1=="go" {print $$2}' go.mod)
VERSION ?= 0.1.0
.PHONY: dev build test test-integration lint fmt security images helm-lint e2e

dev:
	go run ./cmd/signin
build:
	CGO_ENABLED=0 go build -trimpath -o bin/signin ./cmd/signin
	CGO_ENABLED=0 go build -trimpath -o bin/bootstrap ./cmd/bootstrap
	CGO_ENABLED=0 go build -trimpath -o bin/demo-product ./examples/demo-product
test:
	go test -race ./...
test-integration:
	go test -tags integration -count=1 ./...
lint:
	golangci-lint run
fmt:
	gofmt -w cmd internal pkg examples
security:
	govulncheck ./...
	gosec -quiet ./...
images:
	VERSION=$(VERSION) ./scripts/build-images.sh
helm-lint:
	helm lint --strict chart/identity
	helm template check chart/identity >/dev/null
e2e:
	./scripts/e2e.sh

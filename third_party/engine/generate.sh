#!/usr/bin/env bash
# Upstream's generation commands, pinned to the v4.19.5 Nx tool versions.
# The private management console is intentionally absent; shared signin owns UI.
set -euo pipefail
export GOTOOLCHAIN=local GOWORK=off
# Security-only dependency updates; no engine source patch.
go get golang.org/x/net@v0.61.0 golang.org/x/crypto@v0.58.0
for tool in google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1 github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.28.0 github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.28.0 github.com/envoyproxy/protoc-gen-validate@v1.3.3 connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.19.1 github.com/rakyll/statik@v0.1.8 github.com/bufbuild/buf/cmd/buf@v1.67.0; do
 go install "$tool"
done
go install ./internal/protoc/protoc-gen-authoption ./internal/protoc/protoc-gen-zitadel
buf generate
mkdir -p openapi/v2/zitadel apps/docs/content/apis/assets
cp -r .artifacts/grpc/github.com/zitadel/zitadel/pkg/grpc/. pkg/grpc/
cp -r .artifacts/grpc/zitadel/. openapi/v2/zitadel/
for generated in internal/api/ui/login/statik/generate.go internal/notification/statik/generate.go internal/statik/generate.go; do go generate "$generated"; done
go run internal/api/assets/generator/asset_generator.go -directory=internal/api/assets/generator/ -assets=apps/docs/content/apis/assets/assets.mdx

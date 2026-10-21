#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go_version=$(awk '$1=="go"{print $2}' go.mod)
for service in signin bootstrap; do
 docker build --build-arg "GO_VERSION=$go_version" --build-arg "SERVICE=$service" -f Dockerfile -t "ghcr.io/alphabravo-oss/identity/$service:${VERSION:-0.1.0}" .
done

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go_version=$(awk '$1=="go"{print $2}' go.mod)
for service in signin bootstrap; do
 docker build --build-arg "GO_VERSION=$go_version" --build-arg "SERVICE=$service" -f Dockerfile -t "ghcr.io/alphabravo-oss/identity/$service:${VERSION:-0.1.0}" .
done

# Pinned vendor mirrors carry the same Go floor as owned services.
for vendor in engine kubectl; do
 docker build --build-arg "GO_VERSION=$go_version" -f "third_party/$vendor/Dockerfile" -t "ghcr.io/alphabravo-oss/identity/vendor-$vendor:${VERSION:-0.1.1}" .
done

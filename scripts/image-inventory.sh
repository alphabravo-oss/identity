#!/usr/bin/env bash
set -euo pipefail
helm template inventory chart/identity | sed -nE 's/^[[:space:]]*image(Name)?:[[:space:]]*"?([^" ]+)"?.*/\2/p' | sort -u

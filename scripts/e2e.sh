#!/usr/bin/env bash
set -euo pipefail
: "${PROOF_DIR:?Set PROOF_DIR to isolated deployment evidence directory}"
node scripts/live.mjs local
node scripts/live.mjs shots
node scripts/live.mjs crawl

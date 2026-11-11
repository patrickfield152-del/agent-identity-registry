#!/usr/bin/env bash
# Type-check the registry contract for the wasm32 target.
set -euo pipefail

cd "$(dirname "$0")/../contracts/registry"

cargo check --target wasm32-unknown-unknown "$@"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUST_MANIFEST="$ROOT_DIR/rust/Cargo.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/build/rust-target}"
export DEVELOPER_DIR="${DEVELOPER_DIR_OVERRIDE:-/Applications/Xcode.app/Contents/Developer}"
export IPHONEOS_DEPLOYMENT_TARGET=16.0

if [[ ! -d "$DEVELOPER_DIR" ]]; then
    echo "Full Xcode was not found at $DEVELOPER_DIR" >&2
    exit 1
fi

export PATH="$DEVELOPER_DIR/usr/bin:$PATH"

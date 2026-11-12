#!/bin/sh
# Host staticlib for the differential harness (same source as the kernel build).
# Pure core, no build-std: links against the prebuilt host std/core. TARGET
# defaults to the host triple; override for CI (e.g. x86_64-unknown-linux-gnu).
set -eu
cd "$(dirname "$0")"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
cargo build --release --locked --target "$TARGET"
echo "staticlib: target/$TARGET/release/libleeway_rs_reparse.a"

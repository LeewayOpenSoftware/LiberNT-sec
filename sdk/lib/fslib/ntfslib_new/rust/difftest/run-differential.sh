#!/bin/sh
# Build the Rust validator (host staticlib) and the differential harness, then run
# it. Exit 0 iff the C reference and the Rust port agree on every input.
#   ITERS   fuzz iterations (default 2000000)
#   CXX     host C++ compiler (default g++)
# Uses the pinned toolchain via rustup when available.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
RUSTDIR="$HERE/.."
ITERS="${ITERS:-2000000}"
CXX="${CXX:-g++}"
TC="nightly-2026-05-24"

( cd "$RUSTDIR"
  if command -v rustup >/dev/null 2>&1; then
    rustup run "$TC" cargo build --release
  else
    cargo build --release
  fi )

RUSTA="$(ls "$RUSTDIR"/target/release/deps/libleeway_rs_reparse-*.a \
            "$RUSTDIR"/target/release/deps/leeway_rs_reparse-*.lib \
            "$RUSTDIR"/target/release/libleeway_rs_reparse.a 2>/dev/null | head -1)"
[ -n "$RUSTA" ] || { echo "rust staticlib not found" >&2; exit 2; }

"$CXX" -std=c++17 -O2 -Wall -Wextra -DREPARSE_DIFF_STANDALONE -I"$HERE" \
    -o "$HERE/reparse_differential" "$HERE/reparse_differential.cpp" "$RUSTA"
exec "$HERE/reparse_differential" "$ITERS"

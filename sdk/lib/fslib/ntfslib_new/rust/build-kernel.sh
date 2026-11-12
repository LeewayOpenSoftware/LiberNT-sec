#!/bin/sh
# Reproducible no_std staticlib for the custom LiberNT kernel target.
# Rust has no alloc here (the validator never allocates), so build-std rebuilds
# only core + compiler_builtins. This is the artifact the private reproducible-
# build gate produces; it is NOT linked into ntoskrnl and is off by default.
set -eu
cd "$(dirname "$0")"
exec cargo build --release --locked \
  --target targets/x86_64-unknown-libernt-kernel.json \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# RUST-POC-RESULTS — C1 reparse validator (differential)

Experimental / private (LiberNT-sec). The C fix remains the production path; this
records the Rust port's differential result against it. No merge to `leeway/main`,
no LBI.

- Branch: `exp/rust-c1-reparse`, based on `sec/reparse-bounds` `33cb9cb5010`
  (same tree as the shared bundle tip `3cf753f338f`; both carry the corrected C
  validator).
- Component: `sdk/lib/fslib/ntfslib_new/rust/` (crate `leeway-rs-reparse`).
- Toolchain: pinned `nightly-2026-05-24` (rustc 1.98.0-nightly 23a3312d9); host
  reference compiled with g++ 13.2 (MinGW-W64 ucrt). Private CI not yet up —
  built and tested locally per the owner decision.

## Differential: `NtfsValidate*`/`NtfsParseNameSurrogate*` (C) vs. Rust port

Harness: `rust/difftest/reparse_differential.cpp` (run via `run-differential.sh`).
Both the C reference and the Rust port are run on every input; the NTSTATUS, and on
success the projected view (tag, flags, substitute/print offsets and lengths), must
agree.

Result (final run, 2,000,000 fuzz iterations + the fixed corpus):

```
reparse_differential: cases=2000031 disagreements=0 (fuzz_iters=2000000)
reparse_differential: coverage validate_ok=813724 parse{ok=1223 invalid=1998806 not_handled=2}
reparse_differential: PASS (C and Rust agree on every input)
```

- **Zero disagreements** across 2,000,031 inputs.
- Coverage is non-vacuous: common-header validation succeeded 813,724 times; the
  parser returned SUCCESS 1,223 times, `STATUS_IO_REPARSE_DATA_INVALID` 1,998,806
  times, and `STATUS_IO_REPARSE_TAG_NOT_HANDLED` 2 times — i.e. every status the
  parser can return is exercised and agrees.
- Fixed corpus (31 inputs) covers, for both symlink and mount-point: the valid
  junction/symlink; the malformed table (substitute/print offset beyond the data,
  range past the end, `offset + length` wrapping a `USHORT`, odd offset, odd length,
  empty substitute name); truncated and header-only buffers; an embedded NUL; plus
  valid variants (relative symlink, empty print name, full span) and other valid
  tags (WOF, third-party with/without GUID, reserved bits).
- Negative control: deleting the odd-offset/length check in the Rust port makes the
  harness report disagreements and exit non-zero, confirming the harness detects
  divergence.

## Notes / remaining items

- The crate builds for the host (differential) now. The reproducible kernel-target
  staticlib (`build-kernel.sh`, `-Zbuild-std=core,compiler_builtins`) is intended
  for the private reproducible-build gate once the self-hosted runner is up; it is
  off by default and never linked into `ntoskrnl`.
- The malformed/exploit corpus stays private to LiberNT-sec; it is not placed in
  LDW or LiberNT-CI. Only summary counts are shared upward.
- Integration is NOT in scope here (owner decision 3): no merge to `leeway/main`,
  no LBI. This is experimental validation only.

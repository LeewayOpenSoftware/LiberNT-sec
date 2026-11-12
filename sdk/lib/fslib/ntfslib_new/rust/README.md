# leeway-rs-reparse — experimental Rust NTFS reparse-data validator (C1)

Experimental, private, off by default. This is a bounded `no_std` Rust port of the
corrected C reparse validator in ntfslib_new, built to be compared against the C
fix, not to replace it. The C validator (`src/filerecord/read/reparse.cpp`) remains
the production path and the primary remediation; nothing here changes it, nothing
here links into `ntoskrnl`, and nothing here goes onto installation media. There is
no merge to `leeway/main` and no LBI cut without separate owner approval.

Authorized by owner decision 1 in
`shared/libernt/kernel/OWNER-DECISIONS-2026-11-12-C1-PRIVCI-INTEGRATION.md`.

## What it is

`src/lib.rs` is a faithful port of three functions from the corrected C validator:

| C function | Rust C-ABI export |
|---|---|
| `NtfsValidateReparseBuffer` | `leeway_rs_ntfs_validate_reparse_buffer` |
| `NtfsParseNameSurrogateReparsePoint` | `leeway_rs_ntfs_parse_name_surrogate_reparse_point` |
| `IsNameRangeValid` (internal helper) | (inlined; not exported) |

It rejects the same things the C fix does: bad offsets and lengths, truncated
buffers, integer overflow of `offset + length`, odd (non-`WCHAR`-aligned) offsets
and lengths, empty substitute names, embedded NULs, and lone/mismatched UTF-16
surrogates. The NT structures (`ReparsePointEx`, `NtfsReparseNameView`, the
symlink/mount-point headers) keep their on-disk layout unchanged.

Properties, enforced by construction:

- **no_std**, no `alloc` — the validator never allocates. It borrows the
  caller-owned buffer and returns a status plus, on success, a zero-copy view.
- **No panic paths.** Every offset/length read goes through bounds-guarded helpers
  (`rd_u16`/`rd_u32` return `Option`), and all arithmetic is checked or provably
  bounded (lengths are `<= 16 KiB`). `panic = "abort"`, and the `#[panic_handler]`
  is unreachable.
- **Deterministic** — pure function of the input bytes; no clock, no global state.

## Build

Pinned toolchain `nightly-2026-05-24` (see `rust-toolchain.toml`), shared with the
lnrspoc PoC.

- Kernel target (reproducible-build artifact; validated in private CI, not linked
  into the OS): `./build-kernel.sh` — builds the `no_std` staticlib for
  `targets/x86_64-unknown-libernt-kernel.json` with `-Zbuild-std=core,compiler_builtins`
  (no `alloc`: this validator never allocates).
- Host (for the differential harness): `./build-host.sh` — plain `cargo build`
  against the prebuilt host `core`, no build-std.

## Differential test — the C fix vs. the Rust port

`difftest/` runs both implementations on identical inputs and asserts the NTSTATUS
(and, on success, the projected view) agree on every one.

```
sh difftest/run-differential.sh          # builds the Rust lib + harness, runs it
ITERS=5000000 sh difftest/run-differential.sh
```

Inputs: the existing regression corpus (the malformed-case table + valid junction
and symlink from `linux/tests/reparse_name_bounds.cpp`, for both symlink and
mount-point), extra valid variants (relative symlink, empty print name, full-span),
other valid tags that must reach `STATUS_IO_REPARSE_TAG_NOT_HANDLED`, and a bounded
deterministic fuzz corpus (fixed seed, buffers `<= 96` bytes).

Fidelity of the C reference: by default the harness compiles the three C functions
**verbatim** from `difftest/reparse_ref_body.inc`, regenerated from the real
`reparse.cpp` by `difftest/gen-ref-body.sh`, over a thin portable shim
(`reparse_ref_shim.h`) whose struct typedefs are asserted (`static_assert`) to match
the shipped ABI sizes. This lets the differential run on any host toolchain without
building the whole library. Where private CI builds the full `ntfslib_linux`, define
`REPARSE_DIFF_LINK_NTFSLIB` to link the compiled library instead; both paths exercise
the identical C logic and Rust port. A negative control (deliberately removing the
odd-offset check from the Rust) was confirmed to make the harness report
disagreements and fail, so a clean pass is not vacuous.

See `RUST-POC-RESULTS.md` for the recorded result.

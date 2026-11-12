/*
 * Standalone differential harness: the corrected C reparse validator vs. the
 * Leeway experimental Rust port, on identical inputs.
 *
 * C reference  : the real NtfsValidateReparseBuffer / IsNameRangeValid /
 *                NtfsParseNameSurrogateReparsePoint, included VERBATIM from
 *                reparse_ref_body.inc (extracted from ntfslib_new reparse.cpp),
 *                over the portable shim.
 * Rust port    : leeway_rs_ntfs_validate_reparse_buffer /
 *                leeway_rs_ntfs_parse_name_surrogate_reparse_point, linked from
 *                the no_std staticlib.
 *
 * Inputs: the existing regression corpus (the 17 malformed cases + valid
 * junction/symlink), extra valid variants, and a bounded deterministic fuzz
 * corpus. Every input is run through both implementations and the NTSTATUS
 * (and, on success, the projected view) must agree. Exit 0 iff zero
 * disagreements. Build and test only; off by default.
 */
/*
 * C reference selection:
 *   REPARSE_DIFF_STANDALONE (default here) -- compile the three corrected
 *       validator functions VERBATIM from reparse_ref_body.inc over the portable
 *       shim. Builds on any host toolchain; this is the locally-verified path.
 *   otherwise -- include the real public/internal headers and link the compiled
 *       ntfslib (the same functions), for private CI where the full library is
 *       built. Both paths exercise the identical C logic and Rust port.
 */
#if !defined(REPARSE_DIFF_STANDALONE) && !defined(REPARSE_DIFF_LINK_NTFSLIB)
#  define REPARSE_DIFF_STANDALONE 1
#endif

#if defined(REPARSE_DIFF_STANDALONE)
#  include "reparse_ref_shim.h"
#  include "reparse_ref_body.inc" /* defines the C reference functions */
#else
#  include <ntfslib_new.h>
#  include <ntfslib_new_internal.h>
/* NtfsValidateReparseBuffer is internal (C++ linkage); declare it to match. */
NTSTATUS NtfsValidateReparseBuffer(const UCHAR* Buffer, ULONG BufferLength,
                                   PReparsePointEx CommonHeader);
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>

/* ---- Rust port (C ABI) ---- */
extern "C" {
NTSTATUS leeway_rs_ntfs_validate_reparse_buffer(const UCHAR* buffer,
                                                ULONG buffer_length,
                                                ReparsePointEx* out_common);
NTSTATUS leeway_rs_ntfs_parse_name_surrogate_reparse_point(const UCHAR* buffer,
                                                           ULONG buffer_length,
                                                           NtfsReparseNameView* view);
}

/* The Rust view must have the same layout as the C one (it is written through a
 * pointer shared by both). */
static_assert(sizeof(NtfsReparseNameView) == 40, "view size");
static_assert(offsetof(NtfsReparseNameView, ReparseTag) == 0, "view off tag");
static_assert(offsetof(NtfsReparseNameView, Flags) == 4, "view off flags");
static_assert(offsetof(NtfsReparseNameView, SubstituteName) == 8, "view off sub");
static_assert(offsetof(NtfsReparseNameView, SubstituteNameLength) == 16, "view off subN");
static_assert(offsetof(NtfsReparseNameView, PrintName) == 24, "view off print");
static_assert(offsetof(NtfsReparseNameView, PrintNameLength) == 32, "view off printN");

static long g_cases = 0;
static long g_disagree = 0;
static int  g_shown = 0;
/* coverage: proves agreement is non-vacuous (SUCCESS and each reject code hit) */
static long g_parse_ok = 0, g_parse_invalid = 0, g_parse_nothandled = 0, g_validate_ok = 0;

static void
show(const char* label, const UCHAR* buf, ULONG len, const char* what)
{
    g_disagree++;
    if (g_shown >= 20)
        return;
    g_shown++;
    std::fprintf(stderr, "DISAGREE [%s] %s; len=%lu bytes=", label, what, (unsigned long)len);
    for (ULONG i = 0; i < len && i < 48; i++)
        std::fprintf(stderr, "%02x", buf[i]);
    std::fprintf(stderr, "\n");
}

/* Run one input through both validators and both parsers; record any mismatch. */
static void
diff_one(const char* label, const UCHAR* buf, ULONG len)
{
    g_cases++;

    /* NtfsValidateReparseBuffer */
    ReparsePointEx cCommon, rCommon;
    std::memset(&cCommon, 0xCC, sizeof cCommon);
    std::memset(&rCommon, 0xCC, sizeof rCommon);
    NTSTATUS cV = NtfsValidateReparseBuffer(buf, len, &cCommon);
    NTSTATUS rV = leeway_rs_ntfs_validate_reparse_buffer(buf, len, &rCommon);
    if (cV != rV)
        show(label, buf, len, "validate status differs");
    else if (NT_SUCCESS(cV) &&
             (cCommon.ReparseType != rCommon.ReparseType ||
              cCommon.ReparseDataLength != rCommon.ReparseDataLength))
        show(label, buf, len, "validate common-header differs");

    /* NtfsParseNameSurrogateReparsePoint */
    NtfsReparseNameView cView, rView;
    NTSTATUS cP = NtfsParseNameSurrogateReparsePoint(buf, len, &cView);
    NTSTATUS rP = leeway_rs_ntfs_parse_name_surrogate_reparse_point(buf, len, &rView);
    if (NT_SUCCESS(cV)) g_validate_ok++;
    if (cP == STATUS_SUCCESS) g_parse_ok++;
    else if (cP == STATUS_IO_REPARSE_TAG_NOT_HANDLED) g_parse_nothandled++;
    else if (cP == STATUS_IO_REPARSE_DATA_INVALID) g_parse_invalid++;
    if (cP != rP) {
        show(label, buf, len, "parse status differs");
        return;
    }
    if (NT_SUCCESS(cP)) {
        bool same =
            cView.ReparseTag == rView.ReparseTag &&
            cView.Flags == rView.Flags &&
            cView.SubstituteNameLength == rView.SubstituteNameLength &&
            cView.PrintNameLength == rView.PrintNameLength &&
            (cView.SubstituteName - buf) == (rView.SubstituteName - buf) &&
            (cView.PrintName - buf) == (rView.PrintName - buf);
        if (!same)
            show(label, buf, len, "parse view differs");
    }
}

/* ---- regression corpus: identical generation to reparse_name_bounds.cpp ---- */
static void Put16(UCHAR* b, ULONG off, USHORT v) { std::memcpy(b + off, &v, sizeof v); }
static void Put32(UCHAR* b, ULONG off, ULONG v) { std::memcpy(b + off, &v, sizeof v); }

static ULONG
Build(UCHAR* b, bool Symlink, USHORT so, USHORT sl, USHORT po, USHORT pl)
{
    static const WCHAR Names[] = { /* L"\\??\\C:\\t\\C:\\t\\" */
        0x5c,0x3f,0x3f,0x5c,0x43,0x3a,0x5c,0x74,0x5c,
        0x43,0x3a,0x5c,0x74,0x5c,0x00 };
    const ULONG NameHeader = Symlink ? 12 : 8;
    const ULONG PathBytes = sizeof(Names) - sizeof(WCHAR);
    const ULONG DataLength = NameHeader + PathBytes;

    std::memset(b, 0, 64 + PathBytes);
    Put32(b, 0, Symlink ? NTFS_IO_REPARSE_TAG_SYMLINK : NTFS_IO_REPARSE_TAG_MOUNT_POINT);
    Put16(b, 4, (USHORT)DataLength);
    Put16(b, 8, so);
    Put16(b, 10, sl);
    Put16(b, 12, po);
    Put16(b, 14, pl);
    if (Symlink)
        Put32(b, 16, 0);
    std::memcpy(b + 8 + NameHeader, Names, PathBytes);
    return 8 + DataLength;
}

static void
run_regression()
{
    UCHAR b[256];
    ULONG len;

    for (int Symlink = 0; Symlink < 2; Symlink++) {
        const char* kind = Symlink ? "regr/symlink" : "regr/mount";

        /* valid */
        len = Build(b, Symlink, 0, 18, 18, 10);
        diff_one(kind, b, len);

        struct { USHORT so, sl, po, pl; const char* what; } Bad[] = {
            { 0x3000, 18, 18, 10, "substitute offset beyond the data" },
            { 20, 18, 0, 0, "substitute range past the end" },
            { 0xFFFE, 4, 0, 0, "substitute offset + length wraps a USHORT" },
            { 1, 18, 18, 10, "odd substitute offset" },
            { 0, 17, 18, 10, "odd substitute length" },
            { 0, 0, 18, 10, "empty substitute name" },
            { 0, 18, 0x2000, 10, "print offset beyond the data" },
            { 0, 18, 24, 10, "print range past the end" },
        };
        for (auto& c : Bad) {
            len = Build(b, Symlink, c.so, c.sl, c.po, c.pl);
            diff_one(kind, b, len);
        }

        /* truncation */
        len = Build(b, Symlink, 0, 18, 18, 10);
        diff_one(kind, b, len - 2);
        diff_one(kind, b, 8 + 4);
    }

    /* embedded NUL inside the substitute name (mount point) */
    len = Build(b, false, 0, 18, 18, 10);
    Put16(b, 16 + 4, 0);
    diff_one("regr/mount", b, len);
}

/* ---- extra valid variants ---- */
static void
run_valid_variants()
{
    UCHAR b[256];
    ULONG len;

    /* relative symlink (Flags = NTFS_SYMLINK_FLAG_RELATIVE) */
    len = Build(b, true, 0, 18, 18, 10);
    Put32(b, 16, NTFS_SYMLINK_FLAG_RELATIVE);
    diff_one("valid/symlink-relative", b, len);

    /* empty print name is allowed (print length 0) */
    len = Build(b, false, 0, 18, 0, 0);
    diff_one("valid/empty-print", b, len);
    len = Build(b, true, 0, 18, 0, 0);
    Put32(b, 16, 0);
    diff_one("valid/empty-print-symlink", b, len);

    /* substitute == print, full span */
    len = Build(b, false, 0, 28, 0, 28);
    diff_one("valid/full-span", b, len);
}

/* ---- other valid tags: common header valid, but not symlink/mount ----
 * These must reach STATUS_IO_REPARSE_TAG_NOT_HANDLED from the parser in both. */
static void
run_other_tags()
{
    UCHAR b[256];

    /* WOF tag 0x80000017: bit 31 set -> common (8-byte) header, no GUID. */
    std::memset(b, 0, sizeof b);
    Put32(b, 0, 0x80000017u);
    Put16(b, 4, 8);          /* 8 bytes of opaque data */
    diff_one("other/wof", b, 8 + 8);

    /* Third-party tag (bit 31 clear) with a non-zero GUID: 24-byte header. */
    std::memset(b, 0, sizeof b);
    Put32(b, 0, 0x00000017u);
    Put16(b, 4, 4);          /* ReparseDataLength counts data after the GUID header */
    b[8] = 0x11;             /* non-zero GUID */
    diff_one("other/thirdparty", b, 24 + 4);

    /* Third-party tag with a ZERO GUID: must be rejected by common validation. */
    std::memset(b, 0, sizeof b);
    Put32(b, 0, 0x00000017u);
    Put16(b, 4, 4);
    diff_one("other/thirdparty-zeroguid", b, 24 + 4);

    /* Reserved bits set in the tag: rejected by common validation. */
    std::memset(b, 0, sizeof b);
    Put32(b, 0, 0x0A000003u); /* a reserved bit (0x0A000000) set */
    Put16(b, 4, 8);
    diff_one("other/reserved-bits", b, 8 + 8);
}

/* ---- bounded deterministic fuzz ---- */
static uint64_t g_state = 0x9E3779B97F4A7C15ULL;
static inline uint32_t rnd() { /* splitmix32-ish, deterministic */
    g_state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return (uint32_t)(z ^ (z >> 31));
}

static void
run_fuzz(long iters)
{
    const ULONG MAXLEN = 96;
    for (long it = 0; it < iters; it++) {
        ULONG len = rnd() % (MAXLEN + 1);
        /* exact-size allocation so an over-read is a heap fault, not silent */
        UCHAR* b = (UCHAR*)std::malloc(len ? len : 1);
        for (ULONG i = 0; i < len; i++)
            b[i] = (UCHAR)rnd();

        if ((rnd() & 1) && len >= 8) {
            /* structured: a plausible symlink/mount header to reach name logic */
            bool sym = rnd() & 1;
            Put32(b, 0, sym ? NTFS_IO_REPARSE_TAG_SYMLINK : NTFS_IO_REPARSE_TAG_MOUNT_POINT);
            ULONG hdr = sym ? 12u : 8u;
            if (len >= 8 + hdr) {
                Put16(b, 4, (USHORT)(len - 8));            /* make ExpectedLength == len */
                Put16(b, 8, (USHORT)(rnd() % (len + 4)));  /* sub offset */
                Put16(b, 10, (USHORT)(rnd() % (len + 4))); /* sub length */
                Put16(b, 12, (USHORT)(rnd() % (len + 4))); /* print offset */
                Put16(b, 14, (USHORT)(rnd() % (len + 4))); /* print length */
                if (sym && len >= 20)
                    Put32(b, 16, rnd() & 3);                /* flags (sometimes invalid) */
            }
        }

        diff_one("fuzz", b, len);
        std::free(b);
    }
}

int
main(int argc, char** argv)
{
    long iters = 500000;
    if (argc > 1)
        iters = std::strtol(argv[1], nullptr, 10);

    run_regression();
    run_valid_variants();
    run_other_tags();
    run_fuzz(iters);

    std::printf("reparse_differential: cases=%ld disagreements=%ld (fuzz_iters=%ld)\n",
                g_cases, g_disagree, iters);
    std::printf("reparse_differential: coverage validate_ok=%ld parse{ok=%ld invalid=%ld not_handled=%ld}\n",
                g_validate_ok, g_parse_ok, g_parse_invalid, g_parse_nothandled);
    if (g_disagree) {
        std::printf("reparse_differential: FAIL\n");
        return 1;
    }
    std::printf("reparse_differential: PASS (C and Rust agree on every input)\n");
    return 0;
}

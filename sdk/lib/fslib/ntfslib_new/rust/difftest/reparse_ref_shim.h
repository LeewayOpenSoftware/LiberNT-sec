/*
 * Portable shim for the standalone differential harness.
 *
 * It lets the three corrected C validator functions from ntfslib_new
 * (src/filerecord/read/reparse.cpp: NtfsValidateReparseBuffer, IsNameRangeValid,
 * NtfsParseNameSurrogateReparsePoint) compile and run on a plain host toolchain
 * (g++/clang) without building the whole NTFS library. The function BODIES are
 * included verbatim from reparse_ref_body.inc (extracted, not retyped); only the
 * NT scalar types, the Rtl* helpers, the status codes and the on-disk structs
 * are supplied here. The struct typedefs are copied verbatim from the real
 * public headers (ntfsattribdef.h, ntfslib_new.h) and their sizes are asserted,
 * so any drift from the shipped ABI fails the build rather than the compare.
 *
 * The authoritative in-tree harness links the real ntfslib_linux instead (see
 * reparse_differential.cpp + linux/CMakeLists.txt); this shim exists only so the
 * zero-disagreement result can be reproduced where that full build is absent.
 */
#ifndef LEEWAY_REPARSE_REF_SHIM_H
#define LEEWAY_REPARSE_REF_SHIM_H

#include <cstdint>
#include <cstring>

/* ---- NT scalar types ---- */
typedef uint8_t  UCHAR;
typedef uint16_t USHORT;
typedef uint16_t WCHAR;            /* UTF-16 code unit; sizeof == 2 by typedef */
typedef uint32_t ULONG;
typedef int32_t  LONG;
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef int32_t  NTSTATUS;
typedef unsigned char BOOLEAN;
typedef UCHAR*   PUCHAR;

#ifndef TRUE
#define TRUE  ((BOOLEAN)1)
#define FALSE ((BOOLEAN)0)
#endif

/* ---- SAL annotations: no-ops on the host ---- */
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_
#define _In_reads_bytes_(x)
#define _In_reads_(x)

/* ---- NTSTATUS codes (exact values, see ntstatus.h) ---- */
#define STATUS_SUCCESS                 ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PARAMETER       ((NTSTATUS)0xC000000DL)
#define STATUS_IO_REPARSE_DATA_INVALID ((NTSTATUS)0xC0000278L)
#define STATUS_IO_REPARSE_TAG_NOT_HANDLED ((NTSTATUS)0xC0000279L)
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

/* ---- reparse constants (match include/public/ntfslib_new.h) ---- */
#define NTFS_MAXIMUM_REPARSE_DATA_BUFFER_SIZE (16 * 1024)
#define NTFS_IO_REPARSE_TAG_MOUNT_POINT ((UINT32)0xA0000003)
#define NTFS_IO_REPARSE_TAG_SYMLINK     ((UINT32)0xA000000C)
#define NTFS_SYMLINK_FLAG_RELATIVE      ((UINT32)0x00000001)

/* ---- GUID (16 bytes) ---- */
typedef struct _GUID {
    ULONG  Data1;
    USHORT Data2;
    USHORT Data3;
    UCHAR  Data4[8];
} GUID;
static_assert(sizeof(GUID) == 16, "GUID layout");

/* ---- $REPARSE_POINT common header (verbatim from ntfsattribdef.h) ---- */
typedef struct
{
    UINT32 ReparseType;                    // Offset 0x00, Size 4
    UINT16 ReparseDataLength;              // Offset 0x04, Size 2
    UINT16 Padding;                        // Offset 0x06, Size 2
} ReparsePointEx, *PReparsePointEx;
static_assert(sizeof(ReparsePointEx) == 8, "ReparsePointEx layout");

typedef struct _ThirdPartyReparsePointEx
{
    ReparsePointEx Header;                 // Offset 0x00, Size 8
    GUID ReparseGUID;                      // Offset 0x08, Size 16
} ThirdPartyReparsePointEx, *PThirdPartyReparsePointEx;
static_assert(sizeof(ThirdPartyReparsePointEx) == 24, "ThirdPartyReparsePointEx layout");

/* ---- validated name view (verbatim from ntfslib_new.h) ---- */
typedef struct NtfsReparseNameView
{
    UINT32 ReparseTag;
    UINT32 Flags;
    const UCHAR* SubstituteName;
    ULONG SubstituteNameLength;
    const UCHAR* PrintName;
    ULONG PrintNameLength;
} NtfsReparseNameView, *PNtfsReparseNameView;

/* ---- Rtl* helpers (faithful semantics) ---- */
static inline void RtlCopyMemory(void* d, const void* s, size_t n) { std::memcpy(d, s, n); }
static inline void RtlZeroMemory(void* d, size_t n) { std::memset(d, 0, n); }
/* RtlCompareMemory returns the count of equal leading bytes (NOT memcmp's sign). */
static inline size_t RtlCompareMemory(const void* a, const void* b, size_t n)
{
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    size_t i = 0;
    while (i < n && pa[i] == pb[i]) i++;
    return i;
}

#endif /* LEEWAY_REPARSE_REF_SHIM_H */

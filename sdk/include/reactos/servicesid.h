/*
 * PROJECT:     LiberNT
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NT SERVICE\<name> service SID derivation (shared by the SCM and lsasrv)
 * COPYRIGHT:   Copyright 2026 Leeway Open Software <281492504+LeewayOpenSoftware@users.noreply.github.com>
 *
 * The service SID is S-1-5-80-<5 sub-authorities>: the 20 byte SHA-1 of the UPPERCASE UTF-16LE service name,
 * read as five little-endian DWORDs (the same derivation that yields the well-known TrustedInstaller SID).
 */

#ifndef _LIBERNT_SERVICESID_H
#define _LIBERNT_SERVICESID_H

#define LSA_SERVICE_SID_SUBAUTH_COUNT       6   /* 80 + five hash DWORDs */
#define LSA_SERVICE_SID_MAX_NAME_CCH        256
#define LSA_SERVICE_SID_LENGTH              (8 + LSA_SERVICE_SID_SUBAUTH_COUNT * 4)

typedef struct _LSA_SVC_SHA_CTX
{
    UCHAR Buffer[64];
    ULONG State[5];
    ULONG Count[2];
} LSA_SVC_SHA_CTX;

NTSYSAPI VOID NTAPI A_SHAInit(_Out_ LSA_SVC_SHA_CTX *Context);
NTSYSAPI VOID NTAPI A_SHAUpdate(_Inout_ LSA_SVC_SHA_CTX *Context, _In_reads_(Size) PUCHAR Buffer, _In_ ULONG Size);
NTSYSAPI VOID NTAPI A_SHAFinal(_Inout_ LSA_SVC_SHA_CTX *Context, _Out_writes_(20) PUCHAR Result);

/*
 * Build the service SID of the (not necessarily NUL terminated) name into Sid, which must hold
 * LSA_SERVICE_SID_LENGTH bytes. A name of 0 or more than LSA_SERVICE_SID_MAX_NAME_CCH characters is refused.
 */
static __inline NTSTATUS
LsaFmtServiceSid(
    _In_reads_(cchName) const WCHAR *pszName,
    _In_ ULONG cchName,
    _Out_writes_bytes_(LSA_SERVICE_SID_LENGTH) PSID Sid)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    LSA_SVC_SHA_CTX Ctx;
    WCHAR Upper[LSA_SERVICE_SID_MAX_NAME_CCH];
    UCHAR Digest[20];
    ULONG i, Dword;
    NTSTATUS Status;

    if (cchName == 0 || cchName > LSA_SERVICE_SID_MAX_NAME_CCH)
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < cchName; i++)
        Upper[i] = RtlUpcaseUnicodeChar(pszName[i]);

    A_SHAInit(&Ctx);
    A_SHAUpdate(&Ctx, (PUCHAR)Upper, cchName * sizeof(WCHAR));
    A_SHAFinal(&Ctx, Digest);

    Status = RtlInitializeSid(Sid, &NtAuthority, LSA_SERVICE_SID_SUBAUTH_COUNT);
    if (!NT_SUCCESS(Status))
        return Status;

    *RtlSubAuthoritySid(Sid, 0) = SECURITY_SERVICE_ID_BASE_RID;
    for (i = 0; i < 5; i++)
    {
        RtlCopyMemory(&Dword, &Digest[i * 4], sizeof(Dword));
        *RtlSubAuthoritySid(Sid, i + 1) = Dword;
    }
    return STATUS_SUCCESS;
}

/* A well-formed service SID (authority 5, first sub-authority 80, five hash sub-authorities)? */
static __inline BOOLEAN
LsaIsServiceSidShape(
    _In_ PSID Sid)
{
    static const SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

    return RtlValidSid(Sid) &&
           RtlEqualMemory(RtlIdentifierAuthoritySid(Sid), &NtAuthority, sizeof(NtAuthority)) &&
           *RtlSubAuthorityCountSid(Sid) == LSA_SERVICE_SID_SUBAUTH_COUNT &&
           *RtlSubAuthoritySid(Sid, 0) == SECURITY_SERVICE_ID_BASE_RID;
}

#endif /* _LIBERNT_SERVICESID_H */

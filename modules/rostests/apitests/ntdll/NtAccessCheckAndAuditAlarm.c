/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests that NtAccessCheckAndAuditAlarm performs a real access check
 * COPYRIGHT:       Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

static GENERIC_MAPPING TestMapping = {0x1, 0x2, 0x4, 0x7};

static
BOOLEAN
SetThreadToken(HANDLE Token)
{
    NTSTATUS Status = NtSetInformationThread(NtCurrentThread(),
                                             ThreadImpersonationToken,
                                             &Token,
                                             sizeof(Token));
    return NT_SUCCESS(Status);
}

static
HANDLE
MakeImpersonationToken(VOID)
{
    HANDLE Token, Dup;
    OBJECT_ATTRIBUTES Oa;
    SECURITY_QUALITY_OF_SERVICE Sqos;

    if (!NT_SUCCESS(NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &Token)))
        return NULL;

    Sqos.Length = sizeof(Sqos);
    Sqos.ImpersonationLevel = SecurityImpersonation;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&Oa, NULL, 0, NULL, NULL);
    Oa.SecurityQualityOfService = &Sqos;
    if (!NT_SUCCESS(NtDuplicateToken(Token, TOKEN_QUERY | TOKEN_IMPERSONATE, &Oa, FALSE, TokenImpersonation, &Dup)))
        Dup = NULL;
    NtClose(Token);
    return Dup;
}

typedef struct
{
    UCHAR Type;
    ACCESS_MASK Mask;
} TEST_ACE;

static
NTSTATUS
Check(const TEST_ACE *Aces, ULONG AceCount, BOOLEAN DaclPresent, ACCESS_MASK Desired,
      ACCESS_MASK *Granted, NTSTATUS *AccessStatus)
{
    static SID_IDENTIFIER_AUTHORITY WorldAuth = {SECURITY_WORLD_SID_AUTHORITY};
    UNICODE_STRING Sub = RTL_CONSTANT_STRING(L"Test");
    UNICODE_STRING Type = RTL_CONSTANT_STRING(L"TestType");
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"TestObject");
    SECURITY_DESCRIPTOR Sd;
    PSID World = NULL;
    PACL Dacl = NULL;
    ULONG Size, i;
    BOOLEAN OnClose = TRUE;
    NTSTATUS Status;

    *Granted = 0xDEADBEEF;
    *AccessStatus = 0x11111111;
    RtlAllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World);
    Size = sizeof(ACL) + AceCount * (sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(World));
    Dacl = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    RtlCreateAcl(Dacl, Size, ACL_REVISION);
    for (i = 0; i < AceCount; i++)
    {
        if (Aces[i].Type == ACCESS_DENIED_ACE_TYPE)
            RtlAddAccessDeniedAce(Dacl, ACL_REVISION, Aces[i].Mask, World);
        else
            RtlAddAccessAllowedAce(Dacl, ACL_REVISION, Aces[i].Mask, World);
    }
    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Sd, World, FALSE);
    RtlSetGroupSecurityDescriptor(&Sd, World, FALSE);
    RtlSetDaclSecurityDescriptor(&Sd, DaclPresent, Dacl, FALSE);

    Status = NtAccessCheckAndAuditAlarm(&Sub, NULL, &Type, &Name, &Sd, Desired, &TestMapping,
                                        FALSE, Granted, AccessStatus, &OnClose);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
    RtlFreeSid(World);
    return Status;
}

START_TEST(NtAccessCheckAndAuditAlarm)
{
    BOOLEAN OldPriv;
    HANDLE Token;
    ACCESS_MASK Granted;
    NTSTATUS Status, AccessStatus;
    static const TEST_ACE DenyWriteAllowAll[] = {{ACCESS_DENIED_ACE_TYPE, 0x2}, {ACCESS_ALLOWED_ACE_TYPE, 0x7}};
    static const TEST_ACE AllowReadWrite[] = {{ACCESS_ALLOWED_ACE_TYPE, 0x3}};
    static const TEST_ACE DenyReadAllowAll[] = {{ACCESS_DENIED_ACE_TYPE, 0x1}, {ACCESS_ALLOWED_ACE_TYPE, 0x7}};

    if (!NT_SUCCESS(RtlAdjustPrivilege(SE_AUDIT_PRIVILEGE, TRUE, FALSE, &OldPriv)))
    {
        skip("SeAuditPrivilege is not available\n");
        return;
    }

    Status = Check(AllowReadWrite, 1, TRUE, 0x1, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_NO_IMPERSONATION_TOKEN);

    Token = MakeImpersonationToken();
    if (Token == NULL || !SetThreadToken(Token))
    {
        skip("Cannot impersonate\n");
        return;
    }

    /* deny ACE must deny */
    Status = Check(DenyReadAllowAll, 2, TRUE, 0x1, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_ACCESS_DENIED);
    ok_hex(Granted, 0);

    /* allow ACE must grant exactly what was asked */
    Status = Check(AllowReadWrite, 1, TRUE, 0x1, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_SUCCESS);
    ok_hex(Granted, 0x1);

    /* a right the DACL does not give must be denied */
    Status = Check(AllowReadWrite, 1, TRUE, 0x4, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_ACCESS_DENIED);
    ok_hex(Granted, 0);

    /* mixed request: all-or-nothing */
    Status = Check(AllowReadWrite, 1, TRUE, 0x1 | 0x4, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_ACCESS_DENIED);

    /* empty DACL grants nothing */
    Status = Check(NULL, 0, TRUE, 0x1, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_ACCESS_DENIED);

    /* NULL DACL grants everything */
    Status = Check(NULL, 0, FALSE, 0x4, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_SUCCESS);
    ok_hex(Granted, 0x4);

    /* MAXIMUM_ALLOWED honours an earlier deny */
    Status = Check(DenyWriteAllowAll, 2, TRUE, MAXIMUM_ALLOWED, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(AccessStatus, STATUS_SUCCESS);
    ok_hex(Granted, 0x5);

    /* unmapped generic bits are refused */
    Status = Check(AllowReadWrite, 1, TRUE, GENERIC_READ, &Granted, &AccessStatus);
    ok_ntstatus(Status, STATUS_GENERIC_NOT_MAPPED);

    SetThreadToken(NULL);
    NtClose(Token);
}

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

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarm(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ AUDIT_EVENT_TYPE AuditType,
    _In_ ULONG Flags,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccessList,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatusList,
    _Out_ PBOOLEAN GenerateOnClose);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ HANDLE ClientToken,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ AUDIT_EVENT_TYPE AuditType,
    _In_ ULONG Flags,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccessList,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatusList,
    _Out_ PBOOLEAN GenerateOnClose);

static UNICODE_STRING Sub = RTL_CONSTANT_STRING(L"Test");
static UNICODE_STRING TypeName = RTL_CONSTANT_STRING(L"TestType");
static UNICODE_STRING ObjName = RTL_CONSTANT_STRING(L"TestObject");

static
VOID
BuildSd(const TEST_ACE *Aces, ULONG AceCount, BOOLEAN DaclPresent, SECURITY_DESCRIPTOR *Sd,
        PSID *World, PACL *Dacl)
{
    static SID_IDENTIFIER_AUTHORITY WorldAuth = {SECURITY_WORLD_SID_AUTHORITY};
    ULONG Size, i;

    *World = NULL;
    RtlAllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, World);
    Size = sizeof(ACL) + AceCount * (sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(*World));
    *Dacl = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    RtlCreateAcl(*Dacl, Size, ACL_REVISION);
    for (i = 0; i < AceCount; i++)
    {
        if (Aces[i].Type == ACCESS_DENIED_ACE_TYPE)
            RtlAddAccessDeniedAce(*Dacl, ACL_REVISION, Aces[i].Mask, *World);
        else
            RtlAddAccessAllowedAce(*Dacl, ACL_REVISION, Aces[i].Mask, *World);
    }
    RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(Sd, *World, FALSE);
    RtlSetGroupSecurityDescriptor(Sd, *World, FALSE);
    RtlSetDaclSecurityDescriptor(Sd, DaclPresent, *Dacl, FALSE);
}

static
VOID
FreeSd(PSID World, PACL Dacl)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
    RtlFreeSid(World);
}

/* Two-entry object type list (an object and one property set below it). With plain ACEs every
   entry must get the same result as the whole object. ClientToken NULL uses the thread's
   impersonation token; otherwise the by-handle variant is called with that token. */
static
NTSTATUS
CheckResultList(const TEST_ACE *Aces, ULONG AceCount, ACCESS_MASK Desired, HANDLE ClientToken,
                ACCESS_MASK Granted[2], NTSTATUS AccessStatus[2])
{
    static GUID ObjectGuid = {0x6f2c1e10, 0x5b1d, 0x4c8e, {0x9a, 0x51, 0x2d, 0x7e, 0x13, 0x40, 0x88, 0x01}};
    static GUID PropertyGuid = {0x6f2c1e10, 0x5b1d, 0x4c8e, {0x9a, 0x51, 0x2d, 0x7e, 0x13, 0x40, 0x88, 0x02}};
    OBJECT_TYPE_LIST List[2];
    SECURITY_DESCRIPTOR Sd;
    PSID World;
    PACL Dacl;
    BOOLEAN OnClose = TRUE;
    NTSTATUS Status;

    List[0].Level = ACCESS_OBJECT_GUID;
    List[0].Sbz = 0;
    List[0].ObjectType = &ObjectGuid;
    List[1].Level = ACCESS_PROPERTY_SET_GUID;
    List[1].Sbz = 0;
    List[1].ObjectType = &PropertyGuid;
    Granted[0] = Granted[1] = 0xDEADBEEF;
    AccessStatus[0] = AccessStatus[1] = 0x11111111;

    BuildSd(Aces, AceCount, TRUE, &Sd, &World, &Dacl);
    if (ClientToken == NULL)
    {
        Status = NtAccessCheckByTypeResultListAndAuditAlarm(&Sub, NULL, &TypeName, &ObjName, &Sd, NULL, Desired,
                                                            AuditEventObjectAccess, 0, List, 2, &TestMapping,
                                                            FALSE, Granted, AccessStatus, &OnClose);
    }
    else
    {
        Status = NtAccessCheckByTypeResultListAndAuditAlarmByHandle(&Sub, NULL, ClientToken, &TypeName, &ObjName,
                                                                    &Sd, NULL, Desired, AuditEventObjectAccess, 0,
                                                                    List, 2, &TestMapping, FALSE, Granted,
                                                                    AccessStatus, &OnClose);
    }
    FreeSd(World, Dacl);
    return Status;
}

static
NTSTATUS
Check(const TEST_ACE *Aces, ULONG AceCount, BOOLEAN DaclPresent, ACCESS_MASK Desired,
      ACCESS_MASK *Granted, NTSTATUS *AccessStatus)
{
    SECURITY_DESCRIPTOR Sd;
    PSID World;
    PACL Dacl;
    BOOLEAN OnClose = TRUE;
    NTSTATUS Status;

    *Granted = 0xDEADBEEF;
    *AccessStatus = 0x11111111;
    BuildSd(Aces, AceCount, DaclPresent, &Sd, &World, &Dacl);

    Status = NtAccessCheckAndAuditAlarm(&Sub, NULL, &TypeName, &ObjName, &Sd, Desired, &TestMapping,
                                        FALSE, Granted, AccessStatus, &OnClose);
    FreeSd(World, Dacl);
    return Status;
}

START_TEST(NtAccessCheckAndAuditAlarm)
{
    BOOLEAN OldPriv;
    HANDLE Token, PrimaryToken;
    ACCESS_MASK Granted, GrantedList[2];
    NTSTATUS Status, AccessStatus, StatusList[2];
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

    /* the by-handle variant refuses a primary token */
    if (NT_SUCCESS(NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &PrimaryToken)))
    {
        Status = CheckResultList(AllowReadWrite, 1, 0x1, PrimaryToken, GrantedList, StatusList);
        ok_ntstatus(Status, STATUS_NO_IMPERSONATION_TOKEN);
        NtClose(PrimaryToken);
    }
    else
    {
        skip("Cannot open the process token\n");
    }

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

    /* result list: every entry gets the object's answer */
    Status = CheckResultList(AllowReadWrite, 1, 0x1, NULL, GrantedList, StatusList);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(StatusList[0], STATUS_SUCCESS);
    ok_ntstatus(StatusList[1], STATUS_SUCCESS);
    ok_hex(GrantedList[0], 0x1);
    ok_hex(GrantedList[1], 0x1);

    Status = CheckResultList(DenyReadAllowAll, 2, 0x1, NULL, GrantedList, StatusList);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(StatusList[0], STATUS_ACCESS_DENIED);
    ok_ntstatus(StatusList[1], STATUS_ACCESS_DENIED);
    ok_hex(GrantedList[0], 0);
    ok_hex(GrantedList[1], 0);

    /* result list with MAXIMUM_ALLOWED honours an earlier deny per entry */
    Status = CheckResultList(DenyWriteAllowAll, 2, MAXIMUM_ALLOWED, NULL, GrantedList, StatusList);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(StatusList[0], STATUS_SUCCESS);
    ok_hex(GrantedList[0], 0x5);
    ok_hex(GrantedList[1], 0x5);

    /* the by-handle variant with an impersonation token gives the same answer */
    Status = CheckResultList(AllowReadWrite, 1, 0x1, Token, GrantedList, StatusList);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ntstatus(StatusList[0], STATUS_SUCCESS);
    ok_hex(GrantedList[0], 0x1);

    SetThreadToken(NULL);
    NtClose(Token);
}

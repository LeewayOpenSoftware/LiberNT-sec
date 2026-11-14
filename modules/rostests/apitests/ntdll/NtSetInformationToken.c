/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtSetInformationToken API
 * COPYRIGHT:       Copyright 2022 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"

static
HANDLE
OpenCurrentToken(VOID)
{
    BOOL Success;
    HANDLE Token;

    Success = OpenProcessToken(GetCurrentProcess(),
                               TOKEN_READ | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                               &Token);
    if (!Success)
    {
        ok(0, "OpenProcessToken() has failed to get the process' token (error code: %lu)!\n", GetLastError());
        return NULL;
    }

    return Token;
}

static
PTOKEN_DEFAULT_DACL
QueryOriginalDefaultDacl(
    _In_ HANDLE Token,
    _Out_ PULONG DaclLength)
{
    NTSTATUS Status;
    PTOKEN_DEFAULT_DACL Dacl;
    ULONG BufferLength;

    *DaclLength = 0;

    Status = NtQueryInformationToken(Token,
                                     TokenDefaultDacl,
                                     NULL,
                                     0,
                                     &BufferLength);
    if (!NT_SUCCESS(Status) && (Status != STATUS_BUFFER_TOO_SMALL))
    {
        ok(0, "Failed to query buffer length, STATUS_BUFFER_TOO_SMALL has to be expected (Status code %lx)!\n", Status);
        return NULL;
    }

    Dacl = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Dacl)
    {
        ok(0, "Failed to allocate from heap for token default DACL (required buffer length %lu)!\n", BufferLength);
        return NULL;
    }

    Status = NtQueryInformationToken(Token,
                                     TokenDefaultDacl,
                                     Dacl,
                                     BufferLength,
                                     &BufferLength);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "Failed to query default DACL (Status code %lx)!\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
        return NULL;
    }

    *DaclLength = BufferLength;
    return Dacl;
}

static
PACL
CreateNewDefaultDacl(
    _Out_ PULONG DaclLength)
{
    NTSTATUS Status;
    PACL Dacl;
    ULONG Length;
    PSID LocalSystemSid;
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

    *DaclLength = 0;

    Status = RtlAllocateAndInitializeSid(&NtAuthority,
                                         1,
                                         SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &LocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "Failed to allocate Local System SID (Status code %lx)!\n", Status);
        return NULL;
    }

    Length = sizeof(ACL) +
                 sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(LocalSystemSid);

    Dacl = RtlAllocateHeap(RtlGetProcessHeap(),
                           HEAP_ZERO_MEMORY,
                           Length);
    if (!Dacl)
    {
        ok(0, "Failed to allocate from heap for DACL!\n");
        RtlFreeHeap(RtlGetProcessHeap(), 0, LocalSystemSid);
        return NULL;
    }

    Status = RtlCreateAcl(Dacl,
                          Length,
                          ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "Failed to create ACL (Status code %lx)!\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LocalSystemSid);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
        return NULL;
    }

    Status = RtlAddAccessAllowedAce(Dacl,
                                    ACL_REVISION,
                                    GENERIC_ALL,
                                    LocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "Failed to add access allowed ACE (Status code %lx)!\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LocalSystemSid);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
        return NULL;
    }

    *DaclLength = Length;
    RtlFreeHeap(RtlGetProcessHeap(), 0, LocalSystemSid);
    return Dacl;
}

static
VOID
SetTokenDefaultDaclTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PACL NewDacl;
    TOKEN_DEFAULT_DACL NewDefaultDacl;
    PTOKEN_DEFAULT_DACL DefaultDacl;
    ULONG OriginalDaclLength, NewDaclLength;

    /*
     * Query the original DACL of the token first,
     * we don't want to leave the token tampered
     * later on.
     */
    DefaultDacl = QueryOriginalDefaultDacl(Token, &OriginalDaclLength);
    if (!DefaultDacl)
    {
        ok(0, "Failed to query token's default DACL!\n");
        return;
    }

    /* Allocate new DACL */
    NewDacl = CreateNewDefaultDacl(&NewDaclLength);
    if (!DefaultDacl)
    {
        ok(0, "Failed to allocate buffer for new DACL!\n");
        RtlFreeHeap(RtlGetProcessHeap(), 0, DefaultDacl);
        return;
    }

    NewDefaultDacl.DefaultDacl = NewDacl;

    /*
     * Set a new DACL for the token.
     */
    Status = NtSetInformationToken(Token,
                                   TokenDefaultDacl,
                                   &NewDefaultDacl,
                                   NewDaclLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Now set the original DACL */
    Status = NtSetInformationToken(Token,
                                   TokenDefaultDacl,
                                   DefaultDacl,
                                   OriginalDaclLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlFreeHeap(RtlGetProcessHeap(), 0, DefaultDacl);
    RtlFreeHeap(RtlGetProcessHeap(), 0, NewDacl);
}

static
VOID
SetTokenSessionIdTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG SessionId, OriginalSessionId, QueriedSessionId, Length;
    HANDLE Caller = NULL, Target = NULL, Previous = NULL;
    TOKEN_PRIVILEGES Privileges;
    BOOL Success, Impersonating = FALSE;
    DWORD Error;

    Status = NtQueryInformationToken(Token, TokenSessionId, &OriginalSessionId,
                                     sizeof(OriginalSessionId), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    SessionId = OriginalSessionId ^ 1;
    Success = OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, TRUE, &Previous);
    Error = GetLastError();
    if (!Success && Error != ERROR_NO_TOKEN)
    {
        ok(FALSE, "OpenThreadToken failed: %lu\n", Error);
        return;
    }
    Success = DuplicateTokenEx(Token, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                              NULL, SecurityImpersonation, TokenImpersonation, &Caller);
    ok(Success, "Caller token duplication failed: %lu\n", GetLastError());
    if (!Success) goto Done;
    Success = DuplicateTokenEx(Token, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                              NULL, SecurityImpersonation, TokenPrimary, &Target);
    ok(Success, "Target token duplication failed: %lu\n", GetLastError());
    if (!Success) goto Done;
    Success = AdjustTokenPrivileges(Caller, TRUE, NULL, 0, NULL, NULL);
    ok(Success, "Disabling private caller privileges failed: %lu\n", GetLastError());
    if (!Success) goto Done;
    Success = SetThreadToken(NULL, Caller);
    ok(Success, "Setting caller token failed: %lu\n", GetLastError());
    if (!Success) goto Done;
    Impersonating = TRUE;
    Status = NtSetInformationToken(Target, TokenSessionId, &SessionId, sizeof(SessionId));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);
    Status = NtQueryInformationToken(Target, TokenSessionId, &QueriedSessionId,
                                     sizeof(QueriedSessionId), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok(QueriedSessionId == OriginalSessionId, "Denied update changed session %lu to %lu\n",
           OriginalSessionId, QueriedSessionId);

    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Success = LookupPrivilegeValue(NULL, SE_TCB_NAME, &Privileges.Privileges[0].Luid);
    ok(Success, "SeTcbPrivilege lookup failed: %lu\n", GetLastError());
    if (!Success) goto Done;
    Success = AdjustTokenPrivileges(Caller, FALSE, &Privileges, 0, NULL, NULL);
    Error = GetLastError();
    ok(Success, "Enabling private caller TCB privilege failed: %lu\n", Error);
    if (!Success) goto Done;
    if (Error == ERROR_NOT_ALL_ASSIGNED)
    {
        skip("The caller has no SeTcbPrivilege for the privileged session cases\n");
        goto Done;
    }
    ok(Error == ERROR_SUCCESS, "Enabling SeTcbPrivilege returned %lu\n", Error);
    if (Error != ERROR_SUCCESS) goto Done;
    Status = NtSetInformationToken(Token, TokenSessionId, &SessionId, sizeof(SessionId));
    ok_ntstatus(Status, STATUS_TOKEN_ALREADY_IN_USE);
    Status = NtQueryInformationToken(Token, TokenSessionId, &QueriedSessionId,
                                     sizeof(QueriedSessionId), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok(QueriedSessionId == OriginalSessionId, "Assigned token session changed to %lu\n", QueriedSessionId);
    Status = NtSetInformationToken(Target, TokenSessionId, &SessionId, sizeof(SessionId));
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQueryInformationToken(Target, TokenSessionId, &QueriedSessionId,
                                     sizeof(QueriedSessionId), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok(QueriedSessionId == SessionId, "Private token session %lu expected %lu\n", QueriedSessionId, SessionId);

Done:
    if (Impersonating)
    {
        Success = SetThreadToken(NULL, Previous);
        ok(Success, "Restoring caller token failed: %lu\n", GetLastError());
    }
    if (Target) CloseHandle(Target);
    if (Caller) CloseHandle(Caller);
    if (Previous) CloseHandle(Previous);
}

static
VOID
SetTokenBadPointerTests(
    _In_ HANDLE Token)
{
    TOKEN_MANDATORY_LABEL Label;
    TOKEN_OWNER Owner;
    NTSTATUS Status;

    Owner.Owner = (PSID)(ULONG_PTR)0x10;
    Status = NtSetInformationToken(Token, TokenOwner, &Owner, sizeof(Owner));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    Label.Label.Sid = (PSID)(ULONG_PTR)0x10;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Status = NtSetInformationToken(Token, TokenIntegrityLevel, &Label, sizeof(Label));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
}

static
BOOLEAN
HoldsTcbPrivilege(
    _In_ HANDLE Token)
{
    UCHAR Buffer[sizeof(TOKEN_PRIVILEGES) + 64 * sizeof(LUID_AND_ATTRIBUTES)];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    ULONG Length, i;
    NTSTATUS Status;

    Status = NtQueryInformationToken(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status))
        return FALSE;

    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == SE_TCB_PRIVILEGE &&
            Privileges->Privileges[i].Luid.HighPart == 0)
            return TRUE;
    }
    return FALSE;
}

/* Windows lets only TCB holders change the mandatory policy, even on the caller's own token */
static
VOID
SetTokenMandatoryPolicyTests(
    _In_ HANDLE Token)
{
    TOKEN_MANDATORY_POLICY Policy;
    NTSTATUS Status;

    if (HoldsTcbPrivilege(Token))
    {
        skip("The token holds SeTcbPrivilege, the refusal cannot be tested\n");
        return;
    }

    Policy.Policy = TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
    Status = NtSetInformationToken(Token, TokenMandatoryPolicy, &Policy, sizeof(Policy));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);

    Policy.Policy = TOKEN_MANDATORY_POLICY_OFF;
    Status = NtSetInformationToken(Token, TokenMandatoryPolicy, &Policy, sizeof(Policy));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);
}

/* A SID pointer into kernel space must be refused by the probe, not read */
static
VOID
SetTokenKernelPointerTests(
    _In_ HANDLE Token)
{
    TOKEN_MANDATORY_LABEL Label;
    NTSTATUS Status;

#ifdef _WIN64
    Label.Label.Sid = (PSID)(ULONG_PTR)0xFFFFF78000000000ULL;
#else
    Label.Label.Sid = (PSID)(ULONG_PTR)0xFFDF0000;
#endif
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Status = NtSetInformationToken(Token, TokenIntegrityLevel, &Label, sizeof(Label));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    Label.Label.Sid = NULL;
    Status = NtSetInformationToken(Token, TokenIntegrityLevel, &Label, sizeof(Label));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
}

/* Setting the primary group moves the default DACL inside the token; the DACL must survive it whole */
static
VOID
SetTokenPrimaryGroupKeepsDaclTests(
    _In_ HANDLE Token)
{
    PTOKEN_DEFAULT_DACL Before, After;
    ULONG BeforeLength, AfterLength, Length;
    UCHAR GroupBuffer[sizeof(TOKEN_PRIMARY_GROUP) + SECURITY_MAX_SID_SIZE];
    PTOKEN_PRIMARY_GROUP Group = (PTOKEN_PRIMARY_GROUP)GroupBuffer;
    NTSTATUS Status;

    Before = QueryOriginalDefaultDacl(Token, &BeforeLength);
    if (!Before)
        return;
    if (Before->DefaultDacl == NULL)
    {
        skip("The token has no default DACL\n");
        RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
        return;
    }

    Status = NtQueryInformationToken(Token, TokenPrimaryGroup, GroupBuffer, sizeof(GroupBuffer), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        /* The token's own primary group is always one of its groups */
        Status = NtSetInformationToken(Token, TokenPrimaryGroup, Group, sizeof(TOKEN_PRIMARY_GROUP));
        ok_ntstatus(Status, STATUS_SUCCESS);

        After = QueryOriginalDefaultDacl(Token, &AfterLength);
        if (After)
        {
            ok(After->DefaultDacl != NULL, "The default DACL is gone\n");
            if (After->DefaultDacl)
            {
                ok(After->DefaultDacl->AclSize == Before->DefaultDacl->AclSize,
                   "Default DACL size %u before, %u after\n",
                   Before->DefaultDacl->AclSize, After->DefaultDacl->AclSize);
                ok(After->DefaultDacl->AclSize == Before->DefaultDacl->AclSize &&
                   RtlEqualMemory(Before->DefaultDacl, After->DefaultDacl, Before->DefaultDacl->AclSize),
                   "The default DACL changed when the primary group was set\n");
            }
            RtlFreeHeap(RtlGetProcessHeap(), 0, After);
        }
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
}

/* Windows refuses the audit policy to non-TCB callers; a wild count must not be walked before that */
typedef struct _TEST_TOKEN_AUDIT_POLICY
{
    ULONG PolicyCount;
    struct
    {
        ULONG Category;
        UCHAR Value;
    } Policies[1];
} TEST_TOKEN_AUDIT_POLICY;

static
VOID
SetTokenAuditPolicyTests(
    _In_ HANDLE Token)
{
    TEST_TOKEN_AUDIT_POLICY Policy;
    NTSTATUS Status;

    if (HoldsTcbPrivilege(Token))
    {
        skip("The token holds SeTcbPrivilege, the refusal cannot be tested\n");
        return;
    }

    Policy.PolicyCount = 1;
    Policy.Policies[0].Category = 0; /* the system category */
    Policy.Policies[0].Value = 0;
    Status = NtSetInformationToken(Token, TokenAuditPolicy, &Policy, sizeof(Policy));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);

    /* A count far beyond the buffer: still the privilege answer, never a walk */
    Policy.PolicyCount = 0x10000000;
    Status = NtSetInformationToken(Token, TokenAuditPolicy, &Policy, sizeof(Policy));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);
}

START_TEST(NtSetInformationToken)
{
    NTSTATUS Status;
    ULONG DummyReturnLength = 0;
    HANDLE Token;

    /* Everything else is NULL */
    Status = NtSetInformationToken(NULL,
                                   TokenOwner,
                                   NULL,
                                   0);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    /* We don't give a token */
    Status = NtSetInformationToken(NULL,
                                   TokenOwner,
                                   NULL,
                                   DummyReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    Token = OpenCurrentToken();

    /* We give a bogus token class */
    Status = NtSetInformationToken(Token,
                                   0xa0a,
                                   NULL,
                                   DummyReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);

    /* Now perform tests for each class */
    SetTokenDefaultDaclTests(Token);
    SetTokenSessionIdTests(Token);
    SetTokenBadPointerTests(Token);
    SetTokenMandatoryPolicyTests(Token);
    SetTokenKernelPointerTests(Token);
    SetTokenPrimaryGroupKeepsDaclTests(Token);
    SetTokenAuditPolicyTests(Token);

    CloseHandle(Token);
}

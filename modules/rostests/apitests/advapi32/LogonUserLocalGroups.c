/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests that lsasrv honors LsaLogonUser LocalGroups only for a
 *              caller holding SeTcbPrivilege, and rejects malformed group lists.
 * COPYRIGHT:   Copyright 2026 LeewayOpenSoftware
 */

#include "precomp.h"
#include <winbase.h>
#include <lm.h>
#include <ntsecapi.h>

#define TEST_USER       L"LntLgGroups"
#define TEST_PASSWORD   L"Lnt!LgGroups#2026q"

/* Exit codes reported by the unprivileged child process. */
#define CHILD_DENIED            0   /* logon denied - the fix works */
#define CHILD_INJECTED          1   /* Administrators was injected - VULNERABLE */
#define CHILD_STRIPPED          2   /* logon succeeded but group absent - also safe */
#define CHILD_SETUP_FAILED      3   /* could not run the scenario - skip */

static
NET_API_STATUS
AddUser(VOID)
{
    USER_INFO_1 Info = { 0 };

    NetUserDel(NULL, TEST_USER);
    Info.usri1_name = (PWSTR)TEST_USER;
    Info.usri1_password = (PWSTR)TEST_PASSWORD;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    return NetUserAdd(NULL, 1, (LPBYTE)&Info, NULL);
}

/* Build a one-entry TOKEN_GROUPS holding the BUILTIN\Administrators SID. */
static
PTOKEN_GROUPS
MakeAdminGroups(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuth = { SECURITY_NT_AUTHORITY };
    PTOKEN_GROUPS Groups;
    PSID AdminSid = NULL;

    if (!AllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid))
        return NULL;

    Groups = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS));
    if (Groups == NULL)
    {
        FreeSid(AdminSid);
        return NULL;
    }

    Groups->GroupCount = 1;
    Groups->Groups[0].Sid = AdminSid;    /* freed by FreeSid via the process teardown */
    Groups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
    return Groups;
}

/*
 * Perform an MSV1_0 interactive logon of TEST_USER through LsaLogonUser with the
 * supplied LocalGroups. Returns the NTSTATUS from LsaLogonUser. On success, if
 * ProbeSid is given, *HasProbe reports whether that SID is present in the token.
 */
static
NTSTATUS
LsaInteractiveLogon(
    _In_ HANDLE LsaHandle,
    _In_ ULONG AuthPackage,
    _In_opt_ PTOKEN_GROUPS Groups,
    _In_opt_ PSID ProbeSid,
    _Out_opt_ PBOOL HasProbe)
{
    LSA_STRING OriginName;
    PMSV1_0_INTERACTIVE_LOGON AuthInfo;
    ULONG AuthInfoLength, DomLen, UserLen, PwdLen;
    TOKEN_SOURCE Source = { "ApiTest", { 0 } };
    PVOID Profile = NULL;
    ULONG ProfileLength = 0;
    LUID LogonId = { 0 };
    HANDLE Token = NULL;
    QUOTA_LIMITS Quota;
    NTSTATUS SubStatus = STATUS_SUCCESS;
    NTSTATUS Status;
    PBYTE Ptr;

    if (HasProbe != NULL)
        *HasProbe = FALSE;

    RtlInitString(&OriginName, "ApiTestLocalGroups");

    DomLen  = (ULONG)(wcslen(L".") * sizeof(WCHAR));
    UserLen = (ULONG)(wcslen(TEST_USER) * sizeof(WCHAR));
    PwdLen  = (ULONG)(wcslen(TEST_PASSWORD) * sizeof(WCHAR));
    AuthInfoLength = sizeof(MSV1_0_INTERACTIVE_LOGON) + DomLen + UserLen + PwdLen;

    AuthInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AuthInfoLength);
    if (AuthInfo == NULL)
        return STATUS_NO_MEMORY;

    AuthInfo->MessageType = MsV1_0InteractiveLogon;
    Ptr = (PBYTE)(AuthInfo + 1);

    AuthInfo->LogonDomainName.Length = (USHORT)DomLen;
    AuthInfo->LogonDomainName.MaximumLength = (USHORT)DomLen;
    AuthInfo->LogonDomainName.Buffer = (PWSTR)Ptr;
    RtlCopyMemory(Ptr, L".", DomLen);
    Ptr += DomLen;

    AuthInfo->UserName.Length = (USHORT)UserLen;
    AuthInfo->UserName.MaximumLength = (USHORT)UserLen;
    AuthInfo->UserName.Buffer = (PWSTR)Ptr;
    RtlCopyMemory(Ptr, TEST_USER, UserLen);
    Ptr += UserLen;

    AuthInfo->Password.Length = (USHORT)PwdLen;
    AuthInfo->Password.MaximumLength = (USHORT)PwdLen;
    AuthInfo->Password.Buffer = (PWSTR)Ptr;
    RtlCopyMemory(Ptr, TEST_PASSWORD, PwdLen);

    Status = LsaLogonUser(LsaHandle, &OriginName, Interactive, AuthPackage,
                          AuthInfo, AuthInfoLength, Groups, &Source,
                          &Profile, &ProfileLength, &LogonId, &Token,
                          &Quota, &SubStatus);

    if (NT_SUCCESS(Status) && Token != NULL)
    {
        if (ProbeSid != NULL && HasProbe != NULL)
        {
            BOOL Member = FALSE;

            CheckTokenMembership(Token, ProbeSid, &Member);
            *HasProbe = Member;
        }
    }

    if (Token != NULL)
        CloseHandle(Token);
    if (Profile != NULL)
        LsaFreeReturnBuffer(Profile);
    HeapFree(GetProcessHeap(), 0, AuthInfo);

    if (!NT_SUCCESS(Status))
        return Status;
    return SubStatus;
}

/* Child entry: run as an unprivileged (no-SeTcb) process, connect untrusted,
 * and attempt to inject Administrators. The exit code reports the outcome. */
static
int
RunUnprivilegedChild(VOID)
{
    LSA_STRING PackageName;
    HANDLE LsaHandle = NULL;
    ULONG AuthPackage = 0;
    PTOKEN_GROUPS Groups;
    BOOL HasAdmin = FALSE;
    NTSTATUS Status;

    if (!NT_SUCCESS(LsaConnectUntrusted(&LsaHandle)))
        return CHILD_SETUP_FAILED;

    RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);
    if (!NT_SUCCESS(LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthPackage)))
    {
        LsaDeregisterLogonProcess(LsaHandle);
        return CHILD_SETUP_FAILED;
    }

    Groups = MakeAdminGroups();
    if (Groups == NULL)
    {
        LsaDeregisterLogonProcess(LsaHandle);
        return CHILD_SETUP_FAILED;
    }

    Status = LsaInteractiveLogon(LsaHandle, AuthPackage, Groups,
                                 Groups->Groups[0].Sid, &HasAdmin);
    LsaDeregisterLogonProcess(LsaHandle);

    if (!NT_SUCCESS(Status))
        return CHILD_DENIED;        /* logon rejected - correct */
    return HasAdmin ? CHILD_INJECTED : CHILD_STRIPPED;
}

/* Build a one-entry TOKEN_GROUPS holding a specific (foreign) logon SID. */
static
PTOKEN_GROUPS
MakeForeignLogonGroups(
    _Out_ PSID *LogonSid)
{
    SID_IDENTIFIER_AUTHORITY NtAuth = { SECURITY_NT_AUTHORITY };
    PTOKEN_GROUPS Groups;
    PSID Sid = NULL;

    *LogonSid = NULL;

    /* A logon SID that is NOT this caller's: S-1-5-5-0x7777-0x7777. */
    if (!AllocateAndInitializeSid(&NtAuth, SECURITY_LOGON_IDS_RID_COUNT,
                                  SECURITY_LOGON_IDS_RID, 0x7777, 0x7777,
                                  0, 0, 0, 0, 0, &Sid))
        return NULL;

    Groups = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS));
    if (Groups == NULL)
    {
        FreeSid(Sid);
        return NULL;
    }

    Groups->GroupCount = 1;
    Groups->Groups[0].Sid = Sid;
    Groups->Groups[0].Attributes = SE_GROUP_LOGON_ID | SE_GROUP_ENABLED |
                                   SE_GROUP_ENABLED_BY_DEFAULT;
    *LogonSid = Sid;
    return Groups;
}

/* Child entry: an unprivileged caller supplying a foreign logon SID must NOT
 * get that exact SID in its token (lsasrv substitutes a fresh one). */
static
int
RunForeignLogonChild(VOID)
{
    LSA_STRING PackageName;
    HANDLE LsaHandle = NULL;
    ULONG AuthPackage = 0;
    PTOKEN_GROUPS Groups;
    PSID LogonSid = NULL;
    BOOL HasForeign = FALSE;
    NTSTATUS Status;

    if (!NT_SUCCESS(LsaConnectUntrusted(&LsaHandle)))
        return CHILD_SETUP_FAILED;

    RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);
    if (!NT_SUCCESS(LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthPackage)))
    {
        LsaDeregisterLogonProcess(LsaHandle);
        return CHILD_SETUP_FAILED;
    }

    Groups = MakeForeignLogonGroups(&LogonSid);
    if (Groups == NULL)
    {
        LsaDeregisterLogonProcess(LsaHandle);
        return CHILD_SETUP_FAILED;
    }

    Status = LsaInteractiveLogon(LsaHandle, AuthPackage, Groups, LogonSid, &HasForeign);
    LsaDeregisterLogonProcess(LsaHandle);

    if (!NT_SUCCESS(Status))
        return CHILD_STRIPPED;      /* logon failed - not the injection bug */
    return HasForeign ? CHILD_INJECTED : CHILD_DENIED;
}

/* Child entry: as an unprivileged (no-SeTcb) process, an untrusted LSA
 * connection must be denied a trusted-only authentication-package call. */
static
int
RunConnectTrustChild(VOID)
{
    LSA_STRING PackageName;
    HANDLE LsaHandle = NULL;
    ULONG AuthPackage = 0;
    MSV1_0_PROTOCOL_MESSAGE_TYPE MsgType = MsV1_0EnumerateUsers;  /* trusted-only */
    PVOID Ret = NULL;
    ULONG RetLen = 0;
    NTSTATUS ProtocolStatus = STATUS_SUCCESS;
    NTSTATUS Status;

    if (!NT_SUCCESS(LsaConnectUntrusted(&LsaHandle)))
        return CHILD_SETUP_FAILED;

    RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);
    if (!NT_SUCCESS(LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthPackage)))
    {
        LsaDeregisterLogonProcess(LsaHandle);
        return CHILD_SETUP_FAILED;
    }

    Status = LsaCallAuthenticationPackage(LsaHandle, AuthPackage, &MsgType,
                                          sizeof(MsgType), &Ret, &RetLen, &ProtocolStatus);
    if (Ret != NULL)
        LsaFreeReturnBuffer(Ret);
    LsaDeregisterLogonProcess(LsaHandle);

    /* The trusted-only query must not succeed for an untrusted caller. */
    if (NT_SUCCESS(Status) && NT_SUCCESS(ProtocolStatus))
        return CHILD_INJECTED;      /* trust boundary breached */
    return CHILD_DENIED;
}

/* Child entry: an unprivileged (no-SeTcb) process must still be able to log on
 * through LogonUserW (advapi32 attaches only benign logon-session groups). A
 * STATUS_PRIVILEGE_NOT_HELD here would be the regression the allow-list fixes. */
static
int
RunLogonUserChild(VOID)
{
    HANDLE Token = NULL;

    SetLastError(0xdeadbeef);
    if (LogonUserW(TEST_USER, L".", TEST_PASSWORD, LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &Token))
    {
        if (Token != NULL)
            CloseHandle(Token);
        return CHILD_DENIED;                 /* 0: logon succeeded - correct */
    }

    if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
        return CHILD_INJECTED;               /* 1: 1314 - the regression */
    return CHILD_STRIPPED;                    /* 2: other failure (env/auth) */
}

/* Spawn this same test exe with a restricted (SeTcb-removed) primary token so
 * it runs one of the unprivileged child routines. Returns the exit code, or -1. */
static
int
SpawnUnprivilegedChild(
    _In_ PCWSTR Sentinel)
{
    HANDLE ProcToken = NULL, Restricted = NULL;
    LUID_AND_ATTRIBUTES Delete[1];
    WCHAR Module[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 32];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo = { 0 };
    DWORD ExitCode = (DWORD)-1;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                          TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &ProcToken))
        return -1;

    if (!LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Delete[0].Luid))
    {
        CloseHandle(ProcToken);
        return -1;
    }
    Delete[0].Attributes = 0;

    /* DeletePrivilegeCount removes SeTcbPrivilege from the new primary token;
     * LsapIsTrustedClient checks for its presence, so it must be removed, not
     * merely disabled. */
    if (!CreateRestrictedToken(ProcToken, 0, 0, NULL, 1, Delete, 0, NULL, &Restricted))
    {
        CloseHandle(ProcToken);
        return -1;
    }

    GetModuleFileNameW(NULL, Module, MAX_PATH);
    StringCchPrintfW(CommandLine, _countof(CommandLine), L"\"%ls\" %ls", Module, Sentinel);

    if (CreateProcessAsUserW(Restricted, NULL, CommandLine, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        WaitForSingleObject(ProcessInfo.hProcess, 30000);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
    }

    CloseHandle(Restricted);
    CloseHandle(ProcToken);
    return (int)ExitCode;
}

/* Bounded adversarial leg: a fixed, named set of malformed group lists fed to a
 * trusted logon. Each must fail gracefully; lsass must survive every case. No
 * iteration/fuzzing - run once, report defects. */
static
VOID
TestMalformedGroups(
    _In_ HANDLE LsaHandle,
    _In_ ULONG AuthPackage)
{
    SID_IDENTIFIER_AUTHORITY NtAuth = { SECURITY_NT_AUTHORITY };
    NTSTATUS Status;

    /* Case A: absurd / overflow-prone GroupCount. */
    {
        TOKEN_GROUPS Groups;
        Groups.GroupCount = 0x40000000;   /* * sizeof(SID_AND_ATTRIBUTES) overflows 32-bit */
        Groups.Groups[0].Sid = NULL;
        Groups.Groups[0].Attributes = 0;
        Status = LsaInteractiveLogon(LsaHandle, AuthPackage, &Groups, NULL, NULL);
        ok(!NT_SUCCESS(Status), "huge count: expected failure, got 0x%08lx\n", Status);
    }

    /* Case B: count/pointer mismatch - GroupCount claims entries but the Sid
     * pointer is bogus (unreadable). */
    {
        TOKEN_GROUPS Groups;
        Groups.GroupCount = 1;
        Groups.Groups[0].Sid = (PSID)(ULONG_PTR)0x1;   /* not a valid address */
        Groups.Groups[0].Attributes = SE_GROUP_ENABLED;
        Status = LsaInteractiveLogon(LsaHandle, AuthPackage, &Groups, NULL, NULL);
        ok(!NT_SUCCESS(Status), "bad Sid pointer: expected failure, got 0x%08lx\n", Status);
    }

    /* Case C: malformed SID (illegal revision). */
    {
        struct { TOKEN_GROUPS g; SID_AND_ATTRIBUTES extra; } Buf;
        BYTE BadSid[8] = { 0xFF, 1, 0, 0, 0, 0, 0, 5 };   /* Revision 0xFF */
        Buf.g.GroupCount = 1;
        Buf.g.Groups[0].Sid = (PSID)BadSid;
        Buf.g.Groups[0].Attributes = SE_GROUP_ENABLED;
        Status = LsaInteractiveLogon(LsaHandle, AuthPackage, &Buf.g, NULL, NULL);
        ok(!NT_SUCCESS(Status), "bad SID revision: expected failure, got 0x%08lx\n", Status);
    }

    (void)NtAuth;
}

START_TEST(LogonUserLocalGroups)
{
    LSA_STRING LogonProcessName, PackageName;
    LSA_OPERATIONAL_MODE Mode = 0;
    HANDLE LsaHandle = NULL;
    ULONG AuthPackage = 0;
    PTOKEN_GROUPS Groups;
    BOOL HasAdmin = FALSE;
    NET_API_STATUS NetStatus;
    NTSTATUS Status;
    int ChildResult;

    /* Child modes: run an unprivileged check and report via the exit code. */
    if (wcsstr(GetCommandLineW(), L"LocalGroupsChild") != NULL)
        ExitProcess((UINT)RunUnprivilegedChild());
    if (wcsstr(GetCommandLineW(), L"ConnectTrustChild") != NULL)
        ExitProcess((UINT)RunConnectTrustChild());
    if (wcsstr(GetCommandLineW(), L"LogonUserChild") != NULL)
        ExitProcess((UINT)RunLogonUserChild());
    if (wcsstr(GetCommandLineW(), L"ForeignLogonChild") != NULL)
        ExitProcess((UINT)RunForeignLogonChild());

    NetStatus = AddUser();
    if (NetStatus != NERR_Success)
    {
        skip("NetUserAdd failed with %lu (need admin)\n", NetStatus);
        return;
    }

    /* A trusted connection needs SeTcbPrivilege. Without it, skip the trusted
     * and adversarial legs; the untrusted-deny leg below is the security check. */
    RtlInitString(&LogonProcessName, "ApiTestLogonLG");
    Status = LsaRegisterLogonProcess(&LogonProcessName, &LsaHandle, &Mode);
    if (NT_SUCCESS(Status))
    {
        RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);
        Status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthPackage);
        ok(NT_SUCCESS(Status), "LsaLookupAuthenticationPackage: 0x%08lx\n", Status);

        if (NT_SUCCESS(Status))
        {
            /* Positive control: a trusted caller MAY add groups (unchanged). */
            Groups = MakeAdminGroups();
            if (Groups != NULL)
            {
                Status = LsaInteractiveLogon(LsaHandle, AuthPackage, Groups, Groups->Groups[0].Sid, &HasAdmin);
                ok(NT_SUCCESS(Status), "trusted logon with LocalGroups: 0x%08lx\n", Status);
                ok(HasAdmin, "trusted caller: Administrators should be present\n");
                FreeSid(Groups->Groups[0].Sid);
                HeapFree(GetProcessHeap(), 0, Groups);
            }

            /* Bounded adversarial leg. */
            TestMalformedGroups(LsaHandle, AuthPackage);

            /* lsass must still answer after the malformed inputs. */
            Status = LsaInteractiveLogon(LsaHandle, AuthPackage, NULL, NULL, NULL);
            ok(NT_SUCCESS(Status), "lsass alive after adversarial cases: 0x%08lx\n", Status);
        }

        LsaDeregisterLogonProcess(LsaHandle);
    }
    else
    {
        skip("LsaRegisterLogonProcess failed 0x%08lx; skipping trusted legs\n", Status);
    }

    /* Core security check: an unprivileged (no-SeTcb) caller must NOT be able to
     * inject Administrators through LocalGroups. */
    ChildResult = SpawnUnprivilegedChild(L"LocalGroupsChild");
    if (ChildResult < 0 || ChildResult == CHILD_SETUP_FAILED)
    {
        skip("could not run unprivileged LocalGroups child (result %d)\n", ChildResult);
    }
    else
    {
        ok(ChildResult != CHILD_INJECTED,
           "unprivileged caller injected Administrators via LocalGroups (EoP)\n");
        trace("LocalGroups child result: %d (0=denied,2=stripped)\n", ChildResult);
    }

    /* Connect-trust check: an unprivileged caller's connection is untrusted, so
     * a trusted-only authentication-package call must be denied. */
    ChildResult = SpawnUnprivilegedChild(L"ConnectTrustChild");
    if (ChildResult < 0 || ChildResult == CHILD_SETUP_FAILED)
    {
        skip("could not run unprivileged connect-trust child (result %d)\n", ChildResult);
    }
    else
    {
        ok(ChildResult != CHILD_INJECTED,
           "unprivileged caller was granted a trusted-only package call\n");
        trace("connect-trust child result: %d (0=denied)\n", ChildResult);
    }

    /* Regression guard: an unprivileged caller must still be able to LogonUser
     * (the benign logon-session groups advapi32 supplies are allowed). */
    ChildResult = SpawnUnprivilegedChild(L"LogonUserChild");
    if (ChildResult < 0)
    {
        skip("could not run unprivileged LogonUser child (result %d)\n", ChildResult);
    }
    else
    {
        ok(ChildResult != CHILD_INJECTED,
           "unprivileged LogonUser got ERROR_PRIVILEGE_NOT_HELD (regression)\n");
        trace("LogonUser child result: %d (0=logon ok,2=other failure)\n", ChildResult);
    }

    /* An unprivileged caller supplying a foreign logon SID must not receive it
     * (lsasrv substitutes a fresh one). */
    ChildResult = SpawnUnprivilegedChild(L"ForeignLogonChild");
    if (ChildResult < 0 || ChildResult == CHILD_SETUP_FAILED)
    {
        skip("could not run unprivileged foreign-logon child (result %d)\n", ChildResult);
    }
    else
    {
        ok(ChildResult != CHILD_INJECTED,
           "unprivileged caller obtained a foreign logon SID in its token\n");
        trace("foreign-logon child result: %d (0=substituted/absent)\n", ChildResult);
    }

    NetUserDel(NULL, TEST_USER);
}

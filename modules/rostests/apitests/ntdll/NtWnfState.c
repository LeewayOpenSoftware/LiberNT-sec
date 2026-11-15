/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test the WNF state name and state data system calls
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <apitest.h>
#include <ndk/rtlfuncs.h>

#define WNF_TEMPORARY_STATE_NAME    3
#define WNF_DATA_SCOPE_MACHINE      4
#define WNF_INFO_STATE_NAME_EXIST   0
#define WNF_INFO_SUBSCRIBERS        1
#define WNF_WRITERS                 4
#define WNF_WRITES_PER_THREAD       64

typedef struct _TEST_WNF_STATE_NAME
{
    ULONG Data[2];
} TEST_WNF_STATE_NAME;

typedef NTSTATUS (NTAPI *PNT_CREATE_WNF_STATE_NAME)(TEST_WNF_STATE_NAME *, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PSECURITY_DESCRIPTOR);
typedef NTSTATUS (NTAPI *PNT_DELETE_WNF_STATE_NAME)(const TEST_WNF_STATE_NAME *);
typedef NTSTATUS (NTAPI *PNT_DELETE_WNF_STATE_DATA)(const TEST_WNF_STATE_NAME *, const VOID *);
typedef NTSTATUS (NTAPI *PNT_UPDATE_WNF_STATE_DATA)(const TEST_WNF_STATE_NAME *, const VOID *, ULONG, PVOID, const VOID *, ULONG, LOGICAL);
typedef NTSTATUS (NTAPI *PNT_QUERY_WNF_STATE_DATA)(const TEST_WNF_STATE_NAME *, PVOID, const VOID *, PULONG, PVOID, PULONG);
typedef NTSTATUS (NTAPI *PNT_QUERY_WNF_STATE_NAME_INFORMATION)(const TEST_WNF_STATE_NAME *, ULONG, const VOID *, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PNT_SUBSCRIBE_WNF_STATE_CHANGE)(const TEST_WNF_STATE_NAME *, ULONG, ULONG, PULONG64);
typedef NTSTATUS (NTAPI *PNT_UNSUBSCRIBE_WNF_STATE_CHANGE)(const TEST_WNF_STATE_NAME *);

static PNT_CREATE_WNF_STATE_NAME pNtCreateWnfStateName;
static PNT_DELETE_WNF_STATE_NAME pNtDeleteWnfStateName;
static PNT_DELETE_WNF_STATE_DATA pNtDeleteWnfStateData;
static PNT_UPDATE_WNF_STATE_DATA pNtUpdateWnfStateData;
static PNT_QUERY_WNF_STATE_DATA pNtQueryWnfStateData;
static PNT_QUERY_WNF_STATE_NAME_INFORMATION pNtQueryWnfStateNameInformation;
static PNT_SUBSCRIBE_WNF_STATE_CHANGE pNtSubscribeWnfStateChange;
static PNT_UNSUBSCRIBE_WNF_STATE_CHANGE pNtUnsubscribeWnfStateChange;

static UCHAR SecurityDescriptorBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
static UCHAR AclBuffer[256];

static PSECURITY_DESCRIPTOR
BuildSecurityDescriptor(VOID)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID Everyone = (PSID)SidBuffer;
    PACL Acl = (PACL)AclBuffer;
    PSECURITY_DESCRIPTOR SecurityDescriptor = (PSECURITY_DESCRIPTOR)SecurityDescriptorBuffer;

    RtlInitializeSid(Everyone, &WorldAuthority, 1);
    *RtlSubAuthoritySid(Everyone, 0) = SECURITY_WORLD_RID;
    RtlCreateAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, Everyone);
    RtlCreateSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(SecurityDescriptor, TRUE, Acl, FALSE);
    return SecurityDescriptor;
}

static UCHAR CurrentUserSidBuffer[SECURITY_MAX_SID_SIZE];
static PSID CurrentUserSid;

static PSID
GetCurrentUserSid(VOID)
{
    HANDLE Token;
    UCHAR InfoBuffer[256];
    PTOKEN_USER UserInfo;
    DWORD Length;

    if (CurrentUserSid != NULL)
        return CurrentUserSid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return NULL;
    Length = sizeof(InfoBuffer);
    if (GetTokenInformation(Token, TokenUser, InfoBuffer, sizeof(InfoBuffer), &Length))
    {
        UserInfo = (PTOKEN_USER)InfoBuffer;
        if (RtlLengthSid(UserInfo->User.Sid) <= sizeof(CurrentUserSidBuffer))
        {
            RtlCopyMemory(CurrentUserSidBuffer, UserInfo->User.Sid,
                          RtlLengthSid(UserInfo->User.Sid));
            CurrentUserSid = (PSID)CurrentUserSidBuffer;
        }
    }
    CloseHandle(Token);
    return CurrentUserSid;
}

static PSECURITY_DESCRIPTOR
BuildDeniedSecurityDescriptor(VOID)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    UCHAR WorldSidBuffer[SECURITY_MAX_SID_SIZE];
    UCHAR SystemSidBuffer[SECURITY_MAX_SID_SIZE];
    PSID Everyone = (PSID)WorldSidBuffer;
    PSID System = (PSID)SystemSidBuffer;
    PACL Acl = (PACL)AclBuffer;
    PSECURITY_DESCRIPTOR SecurityDescriptor = (PSECURITY_DESCRIPTOR)SecurityDescriptorBuffer;
    PSID UserSid = GetCurrentUserSid();

    RtlInitializeSid(Everyone, &WorldAuthority, 1);
    *RtlSubAuthoritySid(Everyone, 0) = SECURITY_WORLD_RID;
    RtlInitializeSid(System, &NtAuthority, 1);
    *RtlSubAuthoritySid(System, 0) = SECURITY_LOCAL_SYSTEM_RID;
    RtlCreateAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    RtlAddAccessDeniedAce(Acl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, Everyone);
    RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, System);
    if (UserSid != NULL)
        RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, UserSid);
    RtlCreateSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(SecurityDescriptor, System, FALSE);
    RtlSetDaclSecurityDescriptor(SecurityDescriptor, TRUE, Acl, FALSE);
    return SecurityDescriptor;
}

static PSECURITY_DESCRIPTOR
BuildEmptySecurityDescriptor(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID System = (PSID)SidBuffer;
    PSECURITY_DESCRIPTOR SecurityDescriptor = (PSECURITY_DESCRIPTOR)SecurityDescriptorBuffer;

    RtlInitializeSid(System, &NtAuthority, 1);
    *RtlSubAuthoritySid(System, 0) = SECURITY_LOCAL_SYSTEM_RID;
    RtlCreateAcl((PACL)AclBuffer, sizeof(ACL), ACL_REVISION);
    RtlCreateSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(SecurityDescriptor, System, FALSE);
    RtlSetDaclSecurityDescriptor(SecurityDescriptor, TRUE, (PACL)AclBuffer, FALSE);
    return SecurityDescriptor;
}

static ULONG
QueryNameInformation(_In_ const TEST_WNF_STATE_NAME *StateName, _In_ ULONG InfoClass, _Out_ NTSTATUS *Status)
{
    ULONG Value = 0xCCCCCCCC;

    *Status = pNtQueryWnfStateNameInformation(StateName, InfoClass, NULL, &Value, sizeof(Value));
    return Value;
}

#define WNF_RACE_SUBSCRIBERS    2
#define WNF_RACE_ITERATIONS     1000
#define WNF_FAULT_ITERATIONS    400

typedef struct _WNF_FAULT_CONTEXT
{
    TEST_WNF_STATE_NAME *StateName;
    PVOID SlotPage;
    volatile LONG Stop;
} WNF_FAULT_CONTEXT, *PWNF_FAULT_CONTEXT;

static DWORD WINAPI
IdWriteFaultThread(_In_ PWNF_FAULT_CONTEXT Context)
{
    ULONG OldProtect;
    LONG Index;

    for (Index = 0; Index < 4000; Index++)
    {
        VirtualProtect(Context->SlotPage, 0x10000, PAGE_NOACCESS, &OldProtect);
        VirtualProtect(Context->SlotPage, 0x10000, PAGE_READWRITE, &OldProtect);
    }
    return 0;
}

static DWORD WINAPI
BackgroundUnsubscribeThread(_In_ PWNF_FAULT_CONTEXT Context)
{
    LONG Index;

    for (Index = 0; Index < WNF_FAULT_ITERATIONS; Index++)
        pNtUnsubscribeWnfStateChange(Context->StateName);
    return 0;
}

static VOID
TestSubscribeIdWriteFault(VOID)
{
    WNF_FAULT_CONTEXT Context;
    TEST_WNF_STATE_NAME StateName = {{0, 0}};
    HANDLE Threads[2];
    ULONG Index, Value = 0;
    DWORD ExitCode;
    NTSTATUS Status;

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Value), BuildSecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "NtCreateWnfStateName returned 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    Context.StateName = &StateName;
    Context.SlotPage = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    ok(Context.SlotPage != NULL, "VirtualAlloc failed with %lu\n", GetLastError());
    if (Context.SlotPage == NULL)
        goto Cleanup;

    Threads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IdWriteFaultThread, &Context, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)BackgroundUnsubscribeThread, &Context, 0, NULL);
    ok((Threads[0] != NULL) && (Threads[1] != NULL), "CreateThread failed with %lu\n", GetLastError());

    /* The page toggle faults the SubscriptionId write after the entry probe
       on some iterations; the background unsubscriber detaches concurrently. */
    for (Index = 0; Index < WNF_FAULT_ITERATIONS; Index++)
    {
        ULONG64 *Slot = (ULONG64*)((PUCHAR)Context.SlotPage + 0x10000 - sizeof(ULONG64));

        Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, Slot);
        if (!NT_SUCCESS(Status) &&
            (Status != STATUS_ACCESS_VIOLATION) &&
            (Status != STATUS_INVALID_PARAMETER) &&
            (Status != STATUS_NOT_FOUND))
        {
            ok(0, "NtSubscribeWnfStateChange returned 0x%08lx\n", Status);
        }
        pNtUnsubscribeWnfStateChange(&StateName);
    }

    WaitForMultipleObjects(2, Threads, TRUE, 60000);
    for (Index = 0; Index < 2; Index++)
    {
        ok(GetExitCodeThread(Threads[Index], &ExitCode) && (ExitCode == 0), "Fault thread %lu failed\n", Index);
        CloseHandle(Threads[Index]);
    }
    VirtualFree(Context.SlotPage, 0, MEM_RELEASE);

    Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, NULL);
    ok(Status == STATUS_SUCCESS, "Subscribe after id-write-fault storm returned 0x%08lx\n", Status);
    Status = pNtUnsubscribeWnfStateChange(&StateName);
    ok(Status == STATUS_SUCCESS, "Unsubscribe after id-write-fault storm returned 0x%08lx\n", Status);

Cleanup:
    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_SUCCESS, "Delete after id-write-fault storm returned 0x%08lx\n", Status);
}

static DWORD WINAPI
SubscribeThread(_In_ PVOID Parameter)
{
    TEST_WNF_STATE_NAME *StateName = Parameter;
    ULONG Index;
    ULONG64 SubscriptionId;

    for (Index = 0; Index < WNF_RACE_ITERATIONS; Index++)
    {
        if (!NT_SUCCESS(pNtSubscribeWnfStateChange(StateName, 0, 1, &SubscriptionId)))
            return 1;
    }

    return 0;
}

static DWORD WINAPI
UnsubscribeThread(_In_ PVOID Parameter)
{
    TEST_WNF_STATE_NAME *StateName = Parameter;
    ULONG Index;
    NTSTATUS Status;

    for (Index = 0; Index < WNF_RACE_ITERATIONS; Index++)
    {
        Status = pNtUnsubscribeWnfStateChange(StateName);
        if (!NT_SUCCESS(Status) && (Status != STATUS_NOT_FOUND) &&
            (Status != STATUS_OBJECT_NAME_NOT_FOUND))
        {
            return 1;
        }
    }

    return 0;
}

static VOID
TestSubscribeUnsubscribeRace(VOID)
{
    TEST_WNF_STATE_NAME StateName = {{0, 0}};
    HANDLE Threads[WNF_RACE_SUBSCRIBERS];
    ULONG Index = 0, Value = 0;
    DWORD ExitCode;
    NTSTATUS Status;

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Value), BuildSecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "NtCreateWnfStateName returned 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    for (Index = 0; Index < WNF_RACE_SUBSCRIBERS; Index++)
    {
        Threads[Index] = CreateThread(NULL, 0, Index == 0 ? SubscribeThread : UnsubscribeThread,
                                      (PVOID)&StateName, 0, NULL);
        ok(Threads[Index] != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Threads[Index] == NULL)
            break;
    }

    if (Index == WNF_RACE_SUBSCRIBERS)
    {
        ok(WaitForMultipleObjects(WNF_RACE_SUBSCRIBERS, Threads, TRUE, 30000) == WAIT_OBJECT_0,
           "Subscribe/unsubscribe race threads did not finish\n");
    }

    for (Index = 0; Index < WNF_RACE_SUBSCRIBERS; Index++)
    {
        if (Threads[Index] == NULL)
            break;
        ok(GetExitCodeThread(Threads[Index], &ExitCode) && (ExitCode == 0), "Race thread %lu failed\n", Index);
        CloseHandle(Threads[Index]);
    }

    Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, NULL);
    ok(Status == STATUS_SUCCESS, "Subscribe after race returned 0x%08lx\n", Status);
    Status = pNtUnsubscribeWnfStateChange(&StateName);
    ok(Status == STATUS_SUCCESS, "Unsubscribe after race returned 0x%08lx\n", Status);
    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_SUCCESS, "Delete after race returned 0x%08lx\n", Status);
}

static VOID
TestSecurityDescriptorEnforcement(VOID)
{
    TEST_WNF_STATE_NAME StateName = {{0, 0}};
    UCHAR Buffer[16];
    ULONG64 SubscriptionId = 0;
    ULONG Stamp, Size;
    ULONG Data = 0x12345678;
    NTSTATUS Status;

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Buffer), NULL);
    ok(Status == STATUS_ACCESS_VIOLATION, "Create with a NULL descriptor returned 0x%08lx\n", Status);

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Buffer), BuildEmptySecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "Create with an empty DACL returned 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Size = sizeof(Buffer);
        Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
        ok(Status == STATUS_ACCESS_DENIED, "Query against an empty DACL returned 0x%08lx\n", Status);
        Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, &SubscriptionId);
        ok(Status == STATUS_ACCESS_DENIED, "Subscribe against an empty DACL returned 0x%08lx\n", Status);
        Status = pNtDeleteWnfStateName(&StateName);
        ok(Status == STATUS_ACCESS_DENIED, "Delete against an empty DACL returned 0x%08lx\n", Status);
    }

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Buffer), BuildDeniedSecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "Create with a denied DACL returned 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Size = sizeof(Buffer);
        Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
        ok(Status == STATUS_ACCESS_DENIED, "Query against a denied DACL returned 0x%08lx\n", Status);

        Status = pNtUpdateWnfStateData(&StateName, &Data, sizeof(Data), NULL, NULL, 0, FALSE);
        ok(Status == STATUS_ACCESS_DENIED, "Update against a denied DACL returned 0x%08lx\n", Status);

        Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, &SubscriptionId);
        ok(Status == STATUS_ACCESS_DENIED, "Subscribe against a denied DACL returned 0x%08lx\n", Status);

        Status = pNtDeleteWnfStateData(&StateName, NULL);
        ok(Status == STATUS_ACCESS_DENIED, "Delete data against a denied DACL returned 0x%08lx\n", Status);

        /* The caller's own-SID allow ACE grants DELETE for cleanup. */
        Status = pNtDeleteWnfStateName(&StateName);
        ok(Status == STATUS_SUCCESS, "Delete name with caller allow ACE returned 0x%08lx\n", Status);
    }
}

static DWORD WINAPI
WriterThread(_In_ PVOID Parameter)
{
    TEST_WNF_STATE_NAME *StateName = Parameter;
    ULONG Index;
    ULONG Value;

    for (Index = 0; Index < WNF_WRITES_PER_THREAD; Index++)
    {
        Value = GetCurrentThreadId() ^ Index;
        if (!NT_SUCCESS(pNtUpdateWnfStateData(StateName, &Value, sizeof(Value), NULL, NULL, 0, FALSE)))
            return 1;
    }

    return 0;
}

static VOID
TestConcurrentUpdates(_In_ const TEST_WNF_STATE_NAME *StateName, _In_ ULONG StartStamp)
{
    HANDLE Threads[WNF_WRITERS];
    ULONG Stamp = 0, Size, Value;
    DWORD ExitCode;
    NTSTATUS Status;
    ULONG Index;

    for (Index = 0; Index < WNF_WRITERS; Index++)
    {
        Threads[Index] = CreateThread(NULL, 0, WriterThread, (PVOID)StateName, 0, NULL);
        ok(Threads[Index] != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Threads[Index] == NULL)
            return;
    }

    ok(WaitForMultipleObjects(WNF_WRITERS, Threads, TRUE, 30000) == WAIT_OBJECT_0, "Writers did not finish\n");
    for (Index = 0; Index < WNF_WRITERS; Index++)
    {
        ok(GetExitCodeThread(Threads[Index], &ExitCode) && (ExitCode == 0), "Writer %lu failed\n", Index);
        CloseHandle(Threads[Index]);
    }

    Size = sizeof(Value);
    Status = pNtQueryWnfStateData(StateName, NULL, NULL, &Stamp, &Value, &Size);
    ok(Status == STATUS_SUCCESS, "NtQueryWnfStateData returned 0x%08lx\n", Status);
    ok(Stamp == StartStamp + WNF_WRITERS * WNF_WRITES_PER_THREAD,
       "Concurrent updates lost changes: stamp %lu, expected %lu\n",
       Stamp, StartStamp + WNF_WRITERS * WNF_WRITES_PER_THREAD);
    ok(Size == sizeof(Value), "Size %lu\n", Size);
}

START_TEST(NtWnfState)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    TEST_WNF_STATE_NAME StateName = {{0, 0}};
    UCHAR Buffer[16];
    ULONG Data = 0x12345678;
    ULONG Stamp, Size, Value;
    ULONG64 SubscriptionId = 0;
    NTSTATUS Status;

    pNtCreateWnfStateName = (PNT_CREATE_WNF_STATE_NAME)GetProcAddress(Ntdll, "NtCreateWnfStateName");
    pNtDeleteWnfStateName = (PNT_DELETE_WNF_STATE_NAME)GetProcAddress(Ntdll, "NtDeleteWnfStateName");
    pNtDeleteWnfStateData = (PNT_DELETE_WNF_STATE_DATA)GetProcAddress(Ntdll, "NtDeleteWnfStateData");
    pNtUpdateWnfStateData = (PNT_UPDATE_WNF_STATE_DATA)GetProcAddress(Ntdll, "NtUpdateWnfStateData");
    pNtQueryWnfStateData = (PNT_QUERY_WNF_STATE_DATA)GetProcAddress(Ntdll, "NtQueryWnfStateData");
    pNtQueryWnfStateNameInformation = (PNT_QUERY_WNF_STATE_NAME_INFORMATION)GetProcAddress(Ntdll, "NtQueryWnfStateNameInformation");
    pNtSubscribeWnfStateChange = (PNT_SUBSCRIBE_WNF_STATE_CHANGE)GetProcAddress(Ntdll, "NtSubscribeWnfStateChange");
    pNtUnsubscribeWnfStateChange = (PNT_UNSUBSCRIBE_WNF_STATE_CHANGE)GetProcAddress(Ntdll, "NtUnsubscribeWnfStateChange");
    if (!pNtCreateWnfStateName || !pNtDeleteWnfStateName || !pNtDeleteWnfStateData || !pNtUpdateWnfStateData ||
        !pNtQueryWnfStateData || !pNtQueryWnfStateNameInformation || !pNtSubscribeWnfStateChange || !pNtUnsubscribeWnfStateChange)
    {
        skip("WNF system calls are not exported\n");
        return;
    }

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Buffer), BuildSecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "NtCreateWnfStateName returned 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    Value = QueryNameInformation(&StateName, WNF_INFO_STATE_NAME_EXIST, &Status);
    ok(Status == STATUS_SUCCESS && Value == 1, "Name exists query: 0x%08lx, %lu\n", Status, Value);

    Stamp = 0xCCCCCCCC;
    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_SUCCESS, "Query of a new name returned 0x%08lx\n", Status);
    ok(Stamp == 0, "New name stamp %lu\n", Stamp);
    ok(Size == 0, "New name size %lu\n", Size);

    Status = pNtUpdateWnfStateData(&StateName, &Data, sizeof(Data), NULL, NULL, 0, FALSE);
    ok(Status == STATUS_SUCCESS, "NtUpdateWnfStateData returned 0x%08lx\n", Status);

    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_SUCCESS, "NtQueryWnfStateData returned 0x%08lx\n", Status);
    ok(Stamp == 1, "Stamp after one update %lu\n", Stamp);
    ok(Size == sizeof(Data) && *(PULONG)Buffer == Data, "Data size %lu value 0x%08lx\n", Size, *(PULONG)Buffer);

    Status = pNtUpdateWnfStateData(&StateName, &Data, sizeof(Data), NULL, NULL, 5, TRUE);
    ok(!NT_SUCCESS(Status), "An update with a stale stamp returned 0x%08lx\n", Status);

    Size = 1;
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "Small buffer query returned 0x%08lx\n", Status);
    ok(Size == sizeof(Data), "Required size %lu\n", Size);

    Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, &SubscriptionId);
    ok(Status == STATUS_SUCCESS, "NtSubscribeWnfStateChange returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_SUBSCRIBERS, &Status);
    ok(Status == STATUS_SUCCESS && Value == 1, "Subscribers present: 0x%08lx, %lu\n", Status, Value);
    Status = pNtUnsubscribeWnfStateChange(&StateName);
    ok(Status == STATUS_SUCCESS, "NtUnsubscribeWnfStateChange returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_SUBSCRIBERS, &Status);
    ok(Status == STATUS_SUCCESS && Value == 0, "Subscribers after unsubscribe: 0x%08lx, %lu\n", Status, Value);

    TestConcurrentUpdates(&StateName, 1);

    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_SUCCESS, "NtDeleteWnfStateName returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_STATE_NAME_EXIST, &Status);
    ok(Status == STATUS_SUCCESS && Value == 0, "Deleted name exists query: 0x%08lx, %lu\n", Status, Value);
    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_OBJECT_NAME_NOT_FOUND, "Query of a deleted name returned 0x%08lx\n", Status);
    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_OBJECT_NAME_NOT_FOUND, "Second delete returned 0x%08lx\n", Status);

    TestSecurityDescriptorEnforcement();
    TestSubscribeUnsubscribeRace();
    TestSubscribeIdWriteFault();
}

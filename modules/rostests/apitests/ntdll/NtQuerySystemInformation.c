/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtQuerySystemInformation
 * COPYRIGHT:   Copyright 2019 Thomas Faber (thomas.faber@reactos.org)
 */

#include "precomp.h"

static
VOID
TestProcessImageName(VOID)
{
    PUNICODE_STRING ImagePath = &NtCurrentPeb()->ProcessParameters->ImagePathName;
    PSYSTEM_PROCESS_INFORMATION Info, Buffer;
    UNICODE_STRING BaseName;
    ULONG Length = 0x40000;
    USHORT Index;
    NTSTATUS Status;

    Index = ImagePath->Length / sizeof(WCHAR);
    while (Index != 0 && ImagePath->Buffer[Index - 1] != L'\\')
        Index--;
    BaseName.Buffer = &ImagePath->Buffer[Index];
    BaseName.Length = BaseName.MaximumLength = ImagePath->Length - Index * sizeof(WCHAR);

    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (!Buffer)
    {
        skip("Could not allocate process information\n");
        return;
    }
    Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Length, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Info = Buffer;
        while (Info->UniqueProcessId != NtCurrentTeb()->ClientId.UniqueProcess && Info->NextEntryOffset != 0)
            Info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
        ok(Info->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess, "Current process not listed\n");
        ok(RtlEqualUnicodeString(&Info->ImageName, &BaseName, TRUE),
           "Image name %.*ls, expected %.*ls\n",
           Info->ImageName.Length / (int)sizeof(WCHAR), Info->ImageName.Buffer,
           BaseName.Length / (int)sizeof(WCHAR), BaseName.Buffer);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

static
VOID
TestHandleCount(VOID)
{
    SYSTEM_HANDLE_INFORMATION Handles;
    PSYSTEM_HANDLE_INFORMATION Buffer;
    ULONG Length = 0;
    ULONG Count;
    NTSTATUS Status;

    RtlFillMemory(&Handles, sizeof(Handles), 0xCC);
    Status = NtQuerySystemInformation(SystemHandleInformation, &Handles, sizeof(Handles), NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Handles.NumberOfHandles != 0xCCCCCCCC, "Handle count not written on a short buffer\n");
    Count = Handles.NumberOfHandles;

    RtlFillMemory(&Handles, sizeof(Handles), 0xCC);
    Status = NtQuerySystemInformation(SystemHandleInformation, &Handles, sizeof(Handles), &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Handles.NumberOfHandles != 0xCCCCCCCC, "Handle count not written on a short buffer\n");
    ok(Length > sizeof(Handles), "Handle information length %lu\n", Length);
    trace("Handle count %lu, length %lu\n", Handles.NumberOfHandles, Length);

    Length += 0x10000;
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (!Buffer)
    {
        skip("Could not allocate handle information\n");
        return;
    }
    Status = NtQuerySystemInformation(SystemHandleInformation, Buffer, Length, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Buffer->NumberOfHandles > 1, "Handle count %lu\n", Buffer->NumberOfHandles);
        ok(Length == FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION, Handles) + Buffer->NumberOfHandles * sizeof(Buffer->Handles[0]),
           "Length %lu for %lu handles\n", Length, Buffer->NumberOfHandles);
        ok(Count <= Buffer->NumberOfHandles + 64 && Count + 64 >= Buffer->NumberOfHandles,
           "Short-buffer count %lu, full count %lu\n", Count, Buffer->NumberOfHandles);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

/*
 * The kernel must never read back what it wrote into the caller's buffer: another thread can
 * rewrite a returned name pointer at any time. A racer keeps pointing every ImageName.Buffer
 * (and PageFileName.Buffer) of the caller's buffer at a canary page; the canary must stay
 * untouched however the race falls.
 */
#define RACE_MAX_FIELDS 512

typedef struct _RACE_CONTEXT
{
    PUCHAR Buffer;
    ULONG FieldOffsets[RACE_MAX_FIELDS];
    ULONG FieldCount;
    PVOID Canary;
    volatile LONG Stop;
} RACE_CONTEXT, *PRACE_CONTEXT;

static
DWORD
WINAPI
RacePointerThread(LPVOID Parameter)
{
    PRACE_CONTEXT Context = Parameter;
    ULONG Index;

    while (!Context->Stop)
    {
        for (Index = 0; Index < Context->FieldCount; Index++)
            *(PVOID volatile *)(Context->Buffer + Context->FieldOffsets[Index]) = Context->Canary;
    }
    return 0;
}

static
BOOLEAN
CanaryIntact(PUCHAR Canary)
{
    ULONG Index;

    for (Index = 0; Index < PAGE_SIZE; Index++)
        if (Canary[Index] != 0xCC)
            return FALSE;
    return TRUE;
}

static
VOID
TestNoReadBackOfReturnedPointers(VOID)
{
    const ULONG Length = 0x80000;
    RACE_CONTEXT Context;
    PSYSTEM_PROCESS_INFORMATION Info;
    PSYSTEM_PAGEFILE_INFORMATION PageFile;
    HANDLE Thread;
    ULONG Offset, Round, ReturnLength;
    NTSTATUS Status;

    RtlZeroMemory(&Context, sizeof(Context));
    Context.Buffer = VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Context.Canary = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Context.Buffer || !Context.Canary)
    {
        skip("Allocation failed\n");
        goto Cleanup;
    }
    RtlFillMemory(Context.Canary, PAGE_SIZE, 0xCC);

    /* Learn where the name pointers land */
    Status = NtQuerySystemInformation(SystemProcessInformation, Context.Buffer, Length, &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    Offset = 0;
    do
    {
        Info = (PSYSTEM_PROCESS_INFORMATION)(Context.Buffer + Offset);
        Context.FieldOffsets[Context.FieldCount++] = Offset + FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, ImageName.Buffer);
        Offset += Info->NextEntryOffset;
    } while (Info->NextEntryOffset && Context.FieldCount < RACE_MAX_FIELDS);

    Thread = CreateThread(NULL, 0, RacePointerThread, &Context, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        for (Round = 0; Round < 2000; Round++)
            NtQuerySystemInformation(SystemProcessInformation, Context.Buffer, Length, &ReturnLength);
        Context.Stop = TRUE;
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    ok(CanaryIntact(Context.Canary), "SystemProcessInformation wrote through a pointer read back from the caller's buffer\n");

    /* Same for the page file name, when there is a page file */
    PageFile = (PSYSTEM_PAGEFILE_INFORMATION)Context.Buffer;
    Status = NtQuerySystemInformation(SystemPageFileInformation, PageFile, Length, &ReturnLength);
    if (!NT_SUCCESS(Status) || ReturnLength == 0)
    {
        skip("No page file (status 0x%lx)\n", Status);
        goto Cleanup;
    }
    Context.FieldCount = 1;
    Context.FieldOffsets[0] = FIELD_OFFSET(SYSTEM_PAGEFILE_INFORMATION, PageFileName.Buffer);
    Context.Stop = FALSE;
    Thread = CreateThread(NULL, 0, RacePointerThread, &Context, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        for (Round = 0; Round < 20000; Round++)
            NtQuerySystemInformation(SystemPageFileInformation, PageFile, Length, &ReturnLength);
        Context.Stop = TRUE;
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    ok(CanaryIntact(Context.Canary), "SystemPageFileInformation wrote through a pointer read back from the caller's buffer\n");

Cleanup:
    if (Context.Buffer) VirtualFree(Context.Buffer, 0, MEM_RELEASE);
    if (Context.Canary) VirtualFree(Context.Canary, 0, MEM_RELEASE);
}

/*
 * A fault on the caller's buffer must not leave a lock behind: the call fails and the system
 * keeps working. Before the fix, a fault while the module list resource was held left it held
 * (and the thread's APC disable count off, which stops the system on the way back to user mode).
 */
static
DWORD
WINAPI
QueryModulesThread(LPVOID Parameter)
{
    ULONG Length = 0;
    PVOID Buffer;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Parameter);
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &Length);
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length + 4096);
    if (!Buffer)
        return STATUS_NO_MEMORY;
    Status = NtQuerySystemInformation(SystemModuleInformation, Buffer, Length + 4096, &Length);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Status;
}

typedef struct _PROTECT_RACE
{
    PUCHAR Page;
    volatile LONG Stop;
} PROTECT_RACE, *PPROTECT_RACE;

static
DWORD
WINAPI
ToggleProtectionThread(LPVOID Parameter)
{
    PPROTECT_RACE Race = Parameter;
    DWORD Old;

    while (!Race->Stop)
    {
        VirtualProtect(Race->Page, PAGE_SIZE, PAGE_NOACCESS, &Old);
        VirtualProtect(Race->Page, PAGE_SIZE, PAGE_READWRITE, &Old);
    }
    return 0;
}

static
VOID
TestFaultingBufferReleasesLocks(VOID)
{
    ULONG Length = 0, ReturnLength, Round;
    PUCHAR Region;
    HANDLE Thread;
    DWORD ExitCode = 0;
    PROTECT_RACE Race;
    NTSTATUS Status;

    /* Modules: the second page cannot be written, so the copy faults part way through */
    Status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    Region = VirtualAlloc(NULL, 2 * PAGE_SIZE + ROUND_TO_PAGES(Length), MEM_RESERVE, PAGE_NOACCESS);
    if (!Region || !VirtualAlloc(Region, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE))
    {
        skip("Allocation failed\n");
        return;
    }
    if (Length <= PAGE_SIZE)
    {
        skip("Module list fits in one page (%lu bytes)\n", Length);
    }
    else
    {
        Status = NtQuerySystemInformation(SystemModuleInformation, Region, Length + PAGE_SIZE, &ReturnLength);
        ok_hex(Status, STATUS_ACCESS_VIOLATION);

        /* Another thread must still get the list, and soon */
        Thread = CreateThread(NULL, 0, QueryModulesThread, NULL, 0, NULL);
        ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Thread)
        {
            ok_eq_ulong(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
            GetExitCodeThread(Thread, &ExitCode);
            ok_hex(ExitCode, STATUS_SUCCESS);
            CloseHandle(Thread);
        }
    }
    VirtualFree(Region, 0, MEM_RELEASE);

    /* Processes: a page of the buffer keeps changing between writable and not, so a fault can
       land while a process is locked. Every call fails or succeeds cleanly, and the system and
       this process carry on (a leaked process lock would stop thread creation here). */
    Length = 0x80000;
    Region = VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Region)
    {
        skip("Allocation failed\n");
        return;
    }
    Race.Page = Region + PAGE_SIZE;
    Race.Stop = FALSE;
    Thread = CreateThread(NULL, 0, ToggleProtectionThread, &Race, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        for (Round = 0; Round < 2000; Round++)
        {
            Status = NtQuerySystemInformation(SystemProcessInformation, Region, Length, &ReturnLength);
            ok(Status == STATUS_SUCCESS || Status == STATUS_ACCESS_VIOLATION,
               "Round %lu: status 0x%lx\n", Round, Status);
            if (Status != STATUS_SUCCESS && Status != STATUS_ACCESS_VIOLATION)
                break;
        }
        Race.Stop = TRUE;
        ok_eq_ulong(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
        CloseHandle(Thread);
    }
    Thread = CreateThread(NULL, 0, QueryModulesThread, NULL, 0, NULL);
    ok(Thread != NULL, "Thread creation failed after the race (%lu)\n", GetLastError());
    if (Thread)
    {
        ok_eq_ulong(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
        CloseHandle(Thread);
    }
    VirtualFree(Region, 0, MEM_RELEASE);
}

/* Setting the current time zone takes SeTimeZonePrivilege (Windows Vista and later) */
static
VOID
TestSetTimeZoneNeedsPrivilege(VOID)
{
    RTL_TIME_ZONE_INFORMATION TimeZone;
    BOOLEAN WasEnabled, Dummy;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemCurrentTimeZoneInformation, &TimeZone, sizeof(TimeZone), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Without the privilege enabled: refused */
    Status = RtlAdjustPrivilege(SE_TIME_ZONE_PRIVILEGE, FALSE, FALSE, &WasEnabled);
    if (!NT_SUCCESS(Status))
    {
        /* Not held at all: the set must be refused too */
        WasEnabled = FALSE;
    }
    Status = NtSetSystemInformation(SystemCurrentTimeZoneInformation, &TimeZone, sizeof(TimeZone));
    ok_hex(Status, STATUS_PRIVILEGE_NOT_HELD);

    /* With it (when this account holds it): the unchanged zone is accepted */
    if (NT_SUCCESS(RtlAdjustPrivilege(SE_TIME_ZONE_PRIVILEGE, TRUE, FALSE, &Dummy)))
    {
        Status = NtSetSystemInformation(SystemCurrentTimeZoneInformation, &TimeZone, sizeof(TimeZone));
        ok_hex(Status, STATUS_SUCCESS);
        RtlAdjustPrivilege(SE_TIME_ZONE_PRIVILEGE, WasEnabled, FALSE, &Dummy);
    }
    else
    {
        skip("This account does not hold SeTimeZonePrivilege\n");
    }
}

START_TEST(NtQuerySystemInformation)
{
    NTSTATUS Status;
    ULONG Length = 0;
    PRTL_PROCESS_MODULES Modules;
    SYSTEM_BASIC_INFORMATION Basic;

    Status = NtQuerySystemInformation(0, NULL, 0, NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    Status = NtQuerySystemInformation(0x80000000, NULL, 0, NULL);
    ok_hex(Status, STATUS_INVALID_INFO_CLASS);

    RtlZeroMemory(&Basic, sizeof(Basic));
    Status = NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Basic.NumberOfPhysicalPages != 0, "No physical memory reported\n");
        ok(SharedUserData->NumberOfPhysicalPages == Basic.NumberOfPhysicalPages,
           "Shared physical pages %lu, system information %lu\n",
           SharedUserData->NumberOfPhysicalPages, Basic.NumberOfPhysicalPages);
        trace("Physical pages: shared %lu, queried %lu\n",
              SharedUserData->NumberOfPhysicalPages, Basic.NumberOfPhysicalPages);
    }

    TestProcessImageName();
    TestHandleCount();
    TestNoReadBackOfReturnedPointers();
    TestFaultingBufferReleasesLocks();
    TestSetTimeZoneNeedsPrivilege();

    /* Both loaded-image lists must be initialized even when no user images
     * have been registered with the kernel's module list. */
    Status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Length >= sizeof(*Modules), "Module information length %lu\n", Length);
    Modules = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length + 4096);
    if (!Modules)
    {
        skip("Could not allocate module information\n");
        return;
    }
    Status = NtQuerySystemInformation(SystemModuleInformation, Modules, Length + 4096, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok(Modules->NumberOfModules != 0, "No kernel modules reported\n");
    RtlFreeHeap(RtlGetProcessHeap(), 0, Modules);
}

/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtSetInformationThread API
 * COPYRIGHT:       Copyright 2020 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"
#include <internal/ps_i.h>

static
void
Test_ThreadPriorityClass(void)
{
    NTSTATUS Status;
    BOOLEAN WasEnabled;
    KPRIORITY *Priority;

    Priority = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KPRIORITY));
    if (Priority == NULL)
    {
        skip("Failed to allocate memory for thread priority variable!\n");
        return;
    }

    /* Assign a priority */
    *Priority = 11;

    /* Everything is NULL */
    Status = NtSetInformationThread(NULL,
                                    ThreadPriority,
                                    NULL,
                                    0);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Give an invalid thread handle */
    Status = NtSetInformationThread(NULL,
                                    ThreadPriority,
                                    Priority,
                                    sizeof(KPRIORITY));
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Don't set any priority to the thread */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    NULL,
                                    sizeof(KPRIORITY));
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* The information length is incorrect */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    Priority,
                                    0);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* The buffer is misaligned and information length is incorrect */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    (PVOID)1,
                                    0);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* The buffer is misaligned */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    (PVOID)1,
                                    sizeof(KPRIORITY));
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* The buffer is misaligned -- try with an alignment size of 2 */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    (PVOID)2,
                                    sizeof(KPRIORITY));
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Set the priority to the current thread */
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    Priority,
                                    sizeof(KPRIORITY));
    ok_hex(Status, STATUS_SUCCESS);

    /*
     * Set the priority as LOW_REALTIME_PRIORITY,
     * we don't have privileges to do so.
    */
    *Priority = LOW_REALTIME_PRIORITY;
    RtlAdjustPrivilege(SE_INC_BASE_PRIORITY_PRIVILEGE, FALSE, FALSE, &WasEnabled);
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadPriority,
                                    Priority,
                                    sizeof(KPRIORITY));
    RtlAdjustPrivilege(SE_INC_BASE_PRIORITY_PRIVILEGE, WasEnabled, FALSE, &WasEnabled);
    ok_hex(Status, STATUS_PRIVILEGE_NOT_HELD);

    HeapFree(GetProcessHeap(), 0, Priority);
}

static
void
Test_ThreadSetAlignmentProbe(void)
{
    ULONG InfoClass;

    /* Iterate over the process info classes and begin the tests */
    for (InfoClass = 0; InfoClass < _countof(PsThreadInfoClass); InfoClass++)
    {
        /* The buffer is misaligned */
        QuerySetThreadValidator(SET,
                                InfoClass,
                                (PVOID)(ULONG_PTR)1,
                                PsThreadInfoClass[InfoClass].RequiredSizeSET,
                                STATUS_DATATYPE_MISALIGNMENT);

        /* We set an invalid buffer address */
        QuerySetThreadValidator(SET,
                                InfoClass,
                                (PVOID)(ULONG_PTR)PsThreadInfoClass[InfoClass].AlignmentSET,
                                PsThreadInfoClass[InfoClass].RequiredSizeSET,
                                STATUS_ACCESS_VIOLATION);

        /* The information length is wrong */
        QuerySetThreadValidator(SET,
                                InfoClass,
                                (PVOID)(ULONG_PTR)PsThreadInfoClass[InfoClass].AlignmentSET,
                                PsThreadInfoClass[InfoClass].RequiredSizeSET - 1,
                                STATUS_INFO_LENGTH_MISMATCH);
    }
}

static
void
Test_ThreadNameInformation(void)
{
    NTSTATUS Status;
    THREAD_NAME_INFORMATION NameInfo;
    UCHAR Buffer[sizeof(THREAD_NAME_INFORMATION) + 256 * sizeof(WCHAR)];
    PTHREAD_NAME_INFORMATION QueryInfo = (PTHREAD_NAME_INFORMATION)Buffer;
    ULONG ReturnLength;
    static const WCHAR TestName[] = L"TestThreadName";
    static const WCHAR TestName2[] = L"UpdatedName";

    /* Set a thread name */
    RtlInitUnicodeString(&NameInfo.ThreadName, TestName);
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadNameInformation,
                                    &NameInfo,
                                    sizeof(NameInfo));
    ok_hex(Status, STATUS_SUCCESS);

    /* Query it back */
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryInformationThread(GetCurrentThread(),
                                      ThreadNameInformation,
                                      Buffer,
                                      sizeof(Buffer),
                                      &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(QueryInfo->ThreadName.Length, (ULONG)(wcslen(TestName) * sizeof(WCHAR)));
    ok(QueryInfo->ThreadName.Buffer != NULL, "Expected non-NULL buffer\n");
    if (QueryInfo->ThreadName.Buffer)
    {
        ok(wcsncmp(QueryInfo->ThreadName.Buffer, TestName,
                   QueryInfo->ThreadName.Length / sizeof(WCHAR)) == 0,
           "Thread name mismatch: got '%.*ls'\n",
           QueryInfo->ThreadName.Length / (int)sizeof(WCHAR),
           QueryInfo->ThreadName.Buffer);
    }

    /* Update the name */
    RtlInitUnicodeString(&NameInfo.ThreadName, TestName2);
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadNameInformation,
                                    &NameInfo,
                                    sizeof(NameInfo));
    ok_hex(Status, STATUS_SUCCESS);

    /* Query the updated name */
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryInformationThread(GetCurrentThread(),
                                      ThreadNameInformation,
                                      Buffer,
                                      sizeof(Buffer),
                                      &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(QueryInfo->ThreadName.Length, (ULONG)(wcslen(TestName2) * sizeof(WCHAR)));
    if (QueryInfo->ThreadName.Buffer)
    {
        ok(wcsncmp(QueryInfo->ThreadName.Buffer, TestName2,
                   QueryInfo->ThreadName.Length / sizeof(WCHAR)) == 0,
           "Updated name mismatch\n");
    }

    /* Clear the name by setting empty string */
    RtlInitUnicodeString(&NameInfo.ThreadName, NULL);
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadNameInformation,
                                    &NameInfo,
                                    sizeof(NameInfo));
    ok_hex(Status, STATUS_SUCCESS);

    /* Query - should be empty */
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryInformationThread(GetCurrentThread(),
                                      ThreadNameInformation,
                                      Buffer,
                                      sizeof(Buffer),
                                      &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(QueryInfo->ThreadName.Length, 0);

    /* Query with too-small buffer should fail with STATUS_BUFFER_TOO_SMALL */
    RtlInitUnicodeString(&NameInfo.ThreadName, TestName);
    Status = NtSetInformationThread(GetCurrentThread(),
                                    ThreadNameInformation,
                                    &NameInfo,
                                    sizeof(NameInfo));
    ok_hex(Status, STATUS_SUCCESS);

    Status = NtQueryInformationThread(GetCurrentThread(),
                                      ThreadNameInformation,
                                      Buffer,
                                      sizeof(THREAD_NAME_INFORMATION) - 1,
                                      &ReturnLength);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok_long(ReturnLength, (ULONG)(sizeof(THREAD_NAME_INFORMATION) + wcslen(TestName) * sizeof(WCHAR)));

    /* Clean up */
    RtlInitUnicodeString(&NameInfo.ThreadName, NULL);
    NtSetInformationThread(GetCurrentThread(),
                           ThreadNameInformation,
                           &NameInfo,
                           sizeof(NameInfo));
}

static
void
Test_ThreadAffinityMask(void)
{
    SYSTEM_BASIC_INFORMATION System;
    PROCESS_BASIC_INFORMATION Process;
    THREAD_BASIC_INFORMATION Thread;
    KAFFINITY Original, Mask;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemBasicInformation, &System, sizeof(System), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &Process, sizeof(Process), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &Thread, sizeof(Thread), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    ok(Process.AffinityMask == System.ActiveProcessorsAffinityMask,
       "Process affinity %Ix, active processors %Ix\n",
       (size_t)Process.AffinityMask, (size_t)System.ActiveProcessorsAffinityMask);
    Original = Thread.AffinityMask;

    Mask = ~(KAFFINITY)0;
    Status = NtSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &Mask, sizeof(Mask));
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &Thread, sizeof(Thread), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Thread.AffinityMask == Process.AffinityMask,
       "Thread affinity %Ix, process affinity %Ix\n", (size_t)Thread.AffinityMask, (size_t)Process.AffinityMask);

    Mask = ~System.ActiveProcessorsAffinityMask;
    if (Mask != 0)
    {
        Status = NtSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &Mask, sizeof(Mask));
        ok_hex(Status, STATUS_INVALID_PARAMETER);
    }

    Status = NtSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &Original, sizeof(Original));
    ok_hex(Status, STATUS_SUCCESS);
}

/* ThreadZeroTlsCell clears one TLS index in every thread of the process. The
 * expansion slots are found through an address kept in the TEB, which is the
 * process's own memory. */
static
void
Test_ThreadZeroTlsCell(void)
{
    PTEB Teb = NtCurrentTeb();
    PVOID *OriginalSlots = Teb->TlsExpansionSlots;
    PVOID *Slots;
    NTSTATUS Status;
    ULONG TlsIndex, Index;
    DWORD Allocated;

    /* A cell in the TEB itself */
    Allocated = TlsAlloc();
    ok(Allocated != TLS_OUT_OF_INDEXES, "TlsAlloc failed with %lu\n", GetLastError());
    if (Allocated != TLS_OUT_OF_INDEXES && Allocated < TLS_MINIMUM_AVAILABLE)
    {
        ok(TlsSetValue(Allocated, (PVOID)(ULONG_PTR)0x1234), "TlsSetValue failed with %lu\n", GetLastError());
        TlsIndex = Allocated;
        Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &TlsIndex, sizeof(TlsIndex));
        ok_hex(Status, STATUS_SUCCESS);
        ok(TlsGetValue(Allocated) == NULL, "The cell still holds %p\n", TlsGetValue(Allocated));
    }
    if (Allocated != TLS_OUT_OF_INDEXES)
        TlsFree(Allocated);

    /* A cell in expansion slots of our own: only that cell is cleared */
    Slots = HeapAlloc(GetProcessHeap(), 0, TLS_EXPANSION_SLOTS * sizeof(PVOID));
    ok(Slots != NULL, "No memory for the expansion slots\n");
    if (Slots == NULL)
        return;

    for (Index = 0; Index < TLS_EXPANSION_SLOTS; Index++)
        Slots[Index] = (PVOID)(ULONG_PTR)(Index + 1);

    Teb->TlsExpansionSlots = Slots;
    TlsIndex = TLS_MINIMUM_AVAILABLE + 5;
    Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &TlsIndex, sizeof(TlsIndex));
    Teb->TlsExpansionSlots = OriginalSlots;
    ok_hex(Status, STATUS_SUCCESS);
    for (Index = 0; Index < TLS_EXPANSION_SLOTS; Index++)
    {
        PVOID Expected = (Index == 5) ? NULL : (PVOID)(ULONG_PTR)(Index + 1);

        ok(Slots[Index] == Expected, "Slot %lu holds %p\n", Index, Slots[Index]);
    }
    HeapFree(GetProcessHeap(), 0, Slots);

#ifdef _WIN64
    /* An address in the system range is not ours to clear: the call neither
     * writes there nor brings the system down. Nothing is mapped at the
     * address, so a system that does write there stops here. */
    Teb->TlsExpansionSlots = (PVOID *)(ULONG_PTR)0xFFFF800000000000ULL;
    TlsIndex = TLS_MINIMUM_AVAILABLE + 5;
    Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &TlsIndex, sizeof(TlsIndex));
    Teb->TlsExpansionSlots = OriginalSlots;
    ok(Status == STATUS_SUCCESS || Status == STATUS_ACCESS_VIOLATION,
       "A system address for the expansion slots gave 0x%lx\n", Status);
#endif

    /* An address where nothing is mapped, in the user range */
    Teb->TlsExpansionSlots = (PVOID *)(ULONG_PTR)0x10000;
    TlsIndex = TLS_MINIMUM_AVAILABLE + 5;
    Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &TlsIndex, sizeof(TlsIndex));
    Teb->TlsExpansionSlots = OriginalSlots;
    ok(Status == STATUS_SUCCESS || Status == STATUS_ACCESS_VIOLATION,
       "An unmapped address for the expansion slots gave 0x%lx\n", Status);
}

static
DWORD
WINAPI
IdleThread(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    return 0;
}

/* The ideal processor is also copied to the TEB of the thread, which the
 * process can have made read-only: the call still works. */
static
void
Test_ThreadIdealProcessorReadOnlyTeb(void)
{
    THREAD_BASIC_INFORMATION Basic;
    HANDLE Thread;
    NTSTATUS Status;
    ULONG IdealProcessor = 0;
    DWORD OldProtect, Ignored;

    Thread = CreateThread(NULL, 0, IdleThread, NULL, CREATE_SUSPENDED, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread == NULL)
        return;

    Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Basic, sizeof(Basic), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status) && Basic.TebBaseAddress != NULL &&
        VirtualProtect(Basic.TebBaseAddress, 1, PAGE_READONLY, &OldProtect))
    {
        /* On success the status is the previous ideal processor */
        Status = NtSetInformationThread(Thread, ThreadIdealProcessor, &IdealProcessor, sizeof(IdealProcessor));
        ok(NT_SUCCESS(Status), "ThreadIdealProcessor with a read-only TEB gave 0x%lx\n", Status);

        ok(VirtualProtect(Basic.TebBaseAddress, 1, OldProtect, &Ignored),
           "The TEB could not be made writable again: %lu\n", GetLastError());
    }
    else
    {
        skip("The TEB of the new thread could not be made read-only\n");
    }

    ResumeThread(Thread);
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "The thread did not end\n");
    CloseHandle(Thread);
}

static volatile LONG TicketStop;

static
DWORD
WINAPI
TicketQueryThread(PVOID Parameter)
{
    HANDLE Target = Parameter;
    RTL_WORK_ON_BEHALF_TICKET_EX Ticket;

    while (!TicketStop)
        NtQueryInformationThread(Target, ThreadWorkOnBehalfTicket, &Ticket, sizeof(Ticket), NULL);

    return 0;
}

/* A thread can be given the ticket of another thread and that ticket can be
 * replaced at any time, while other threads ask for it. The thread a ticket
 * names is kept only by the ticket once it has ended and its handle is
 * closed, so replacing the ticket frees it. Only the survival of the system
 * is checked: statuses differ between systems. */
static
void
Test_ThreadWorkOnBehalfTicketRace(void)
{
    ALPC_WORK_ON_BEHALF_TICKET Ticket;
    THREAD_BASIC_INFORMATION Basic;
    KERNEL_USER_TIMES Times;
    HANDLE Target, Query, Named;
    NTSTATUS Status;
    ULONG Round;

    Target = CreateThread(NULL, 0, IdleThread, NULL, CREATE_SUSPENDED, NULL);
    ok(Target != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Target == NULL)
        return;

    TicketStop = 0;
    Query = CreateThread(NULL, 0, TicketQueryThread, Target, 0, NULL);
    ok(Query != NULL, "CreateThread failed with %lu\n", GetLastError());

    for (Round = 0; Query != NULL && Round < 2000; Round++)
    {
        Named = CreateThread(NULL, 0, IdleThread, NULL, 0, NULL);
        if (Named == NULL)
            break;

        Status = NtQueryInformationThread(Named, ThreadBasicInformation, &Basic, sizeof(Basic), NULL);
        if (NT_SUCCESS(Status))
            Status = NtQueryInformationThread(Named, ThreadTimes, &Times, sizeof(Times), NULL);
        if (NT_SUCCESS(Status))
        {
            Ticket.ThreadId = HandleToUlong(Basic.ClientId.UniqueThread);
            Ticket.ThreadCreationTimeLow = Times.CreateTime.LowPart;
            NtSetInformationThread(Target, ThreadWorkOnBehalfTicket, &Ticket, sizeof(Ticket));
        }

        /* From here the ticket alone keeps the thread it names */
        WaitForSingleObject(Named, 10000);
        CloseHandle(Named);

        /* And this lets go of it, while the other thread asks for the ticket */
        RtlZeroMemory(&Ticket, sizeof(Ticket));
        NtSetInformationThread(Target, ThreadWorkOnBehalfTicket, &Ticket, sizeof(Ticket));
    }

    TicketStop = 1;
    if (Query != NULL)
    {
        ok(WaitForSingleObject(Query, 10000) == WAIT_OBJECT_0, "The asking thread did not end\n");
        CloseHandle(Query);
    }

    ResumeThread(Target);
    ok(WaitForSingleObject(Target, 10000) == WAIT_OBJECT_0, "The thread did not end\n");
    CloseHandle(Target);
    ok(Round > 0, "No round was run\n");
}

START_TEST(NtSetInformationThread)
{
    Test_ThreadPriorityClass();
    Test_ThreadSetAlignmentProbe();
    Test_ThreadNameInformation();
    Test_ThreadAffinityMask();
    Test_ThreadZeroTlsCell();
    Test_ThreadIdealProcessorReadOnlyTeb();
    Test_ThreadWorkOnBehalfTicketRace();
}

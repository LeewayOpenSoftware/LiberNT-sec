/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     A thread's user context read and written while it runs on a kernel stack
 *              expansion: the walk to the trap frame crosses back to the original stack
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>
#include <ndk/ketypes.h>

NTKERNELAPI
NTSTATUS
NTAPI
PsGetContextThread(
    _In_ PETHREAD Thread,
    _Inout_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE PreviousMode);

NTKERNELAPI
NTSTATUS
NTAPI
PsSetContextThread(
    _In_ PETHREAD Thread,
    _In_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE PreviousMode);

/* More than a thread stack holds, so the callout always runs on a new stack */
#define EXPANSION_SIZE (KERNEL_LARGE_STACK_SIZE - KERNEL_STACK_SIZE)
#define GUARD_COUNT 16
#define GUARD_VALUE(Index) (0x5A5A0000A5A50000ULL | (Index))
#define CONTEXT_WAIT_MS 10000
#define TAG_CONTEXT_TEST 'xCtK'

typedef struct _EXPANDED_CONTEXT
{
    PETHREAD Target;
    KEVENT Ready;
    KEVENT Done;
    BOOLEAN OnNewStack;
    BOOLEAN GuardIntact;
    NTSTATUS GetStatus;
    NTSTATUS SetStatus;
    NTSTATUS GetAgainStatus;
    CONTEXT Read;
    CONTEXT Written;
    CONTEXT ReadAgain;
} EXPANDED_CONTEXT, *PEXPANDED_CONTEXT;

static
VOID
NTAPI
ExpandedCallout(
    _In_ PVOID Parameter)
{
    PEXPANDED_CONTEXT Context = Parameter;
    volatile ULONG64 Guard[GUARD_COUNT];
    ULONG_PTR Low, High, Initial;
    LARGE_INTEGER Timeout;
    ULONG Index;

    for (Index = 0; Index < GUARD_COUNT; Index++)
        Guard[Index] = GUARD_VALUE(Index);

    /* The stack limits now describe the new stack; the trap frame stays below InitialStack */
    IoGetStackLimits(&Low, &High);
    Initial = (ULONG_PTR)KeGetCurrentThread()->InitialStack;
    Context->OnNewStack = ((ULONG_PTR)Guard >= Low) && ((ULONG_PTR)Guard < High) &&
                          ((Initial <= Low) || (Initial > High));

    /* The other thread's context APCs run here, on the new stack */
    KeSetEvent(&Context->Ready, IO_NO_INCREMENT, FALSE);
    Timeout.QuadPart = -10000LL * CONTEXT_WAIT_MS;
    KeWaitForSingleObject(&Context->Done, Executive, KernelMode, FALSE, &Timeout);

    Context->GuardIntact = TRUE;
    for (Index = 0; Index < GUARD_COUNT; Index++)
    {
        if (Guard[Index] != GUARD_VALUE(Index))
            Context->GuardIntact = FALSE;
    }
}

static
VOID
NTAPI
ContextWorker(
    _In_ PVOID Parameter)
{
    PEXPANDED_CONTEXT Context = Parameter;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    Timeout.QuadPart = -10000LL * CONTEXT_WAIT_MS;
    Status = KeWaitForSingleObject(&Context->Ready, Executive, KernelMode, FALSE, &Timeout);
    if (Status == STATUS_SUCCESS)
    {
        Context->Read.ContextFlags = CONTEXT_FULL;
        Context->GetStatus = PsGetContextThread(Context->Target, &Context->Read, KernelMode);

        /* Write back what was read: a walk that ends on the trap frame changes nothing */
        if (NT_SUCCESS(Context->GetStatus))
        {
            Context->Written = Context->Read;
            Context->Written.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
            Context->SetStatus = PsSetContextThread(Context->Target, &Context->Written, KernelMode);
        }

        Context->ReadAgain.ContextFlags = CONTEXT_FULL;
        Context->GetAgainStatus = PsGetContextThread(Context->Target, &Context->ReadAgain, KernelMode);
    }

    KeSetEvent(&Context->Done, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
CheckNonVolatiles(
    _In_ PCONTEXT Expected,
    _In_ PCONTEXT Actual,
    _In_ PCSTR What)
{
    ok(Actual->Rip == Expected->Rip, "%s: Rip %I64x, expected %I64x\n", What, Actual->Rip, Expected->Rip);
    ok(Actual->Rsp == Expected->Rsp, "%s: Rsp %I64x, expected %I64x\n", What, Actual->Rsp, Expected->Rsp);
    ok(Actual->Rbx == Expected->Rbx, "%s: Rbx %I64x, expected %I64x\n", What, Actual->Rbx, Expected->Rbx);
    ok(Actual->Rbp == Expected->Rbp, "%s: Rbp %I64x, expected %I64x\n", What, Actual->Rbp, Expected->Rbp);
    ok(Actual->Rsi == Expected->Rsi, "%s: Rsi %I64x, expected %I64x\n", What, Actual->Rsi, Expected->Rsi);
    ok(Actual->Rdi == Expected->Rdi, "%s: Rdi %I64x, expected %I64x\n", What, Actual->Rdi, Expected->Rdi);
    ok(Actual->R12 == Expected->R12, "%s: R12 %I64x, expected %I64x\n", What, Actual->R12, Expected->R12);
    ok(Actual->R13 == Expected->R13, "%s: R13 %I64x, expected %I64x\n", What, Actual->R13, Expected->R13);
    ok(Actual->R14 == Expected->R14, "%s: R14 %I64x, expected %I64x\n", What, Actual->R14, Expected->R14);
    ok(Actual->R15 == Expected->R15, "%s: R15 %I64x, expected %I64x\n", What, Actual->R15, Expected->R15);
}

START_TEST(KeContextExpandedStack)
{
    PEXPANDED_CONTEXT Context;
    CONTEXT Reference;
    HANDLE ThreadHandle;
    PVOID WorkerThread = NULL;
    NTSTATUS Status;

    if (skip((ExGetPreviousMode() == UserMode) && (KeGetCurrentThread()->TrapFrame != NULL),
             "Needs a thread that entered the kernel from user mode\n"))
    {
        return;
    }

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), TAG_CONTEXT_TEST);
    if (skip(Context != NULL, "No memory\n"))
        return;
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Target = PsGetCurrentThread();
    KeInitializeEvent(&Context->Ready, NotificationEvent, FALSE);
    KeInitializeEvent(&Context->Done, NotificationEvent, FALSE);

    /* The user context as the thread reads it on its own stack */
    RtlZeroMemory(&Reference, sizeof(Reference));
    Reference.ContextFlags = CONTEXT_FULL;
    Status = PsGetContextThread(PsGetCurrentThread(), &Reference, KernelMode);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, ContextWorker, Context);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    Status = ObReferenceObjectByHandle(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, &WorkerThread, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ZwClose(ThreadHandle);

    Status = KeExpandKernelStackAndCalloutEx(ExpandedCallout, Context, EXPANSION_SIZE, TRUE, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        /* Let the worker go without touching this thread */
        KeSetEvent(&Context->Done, IO_NO_INCREMENT, FALSE);
    }

    if (WorkerThread != NULL)
    {
        KeWaitForSingleObject(WorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WorkerThread);
    }
    else
    {
        /* The worker still uses the context: let it finish before it is freed */
        KeWaitForSingleObject(&Context->Done, Executive, KernelMode, FALSE, NULL);
    }
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    ok(Context->OnNewStack, "The callout did not run on a new stack\n");
    ok(Context->GuardIntact, "Writing the user context changed the callout's frame\n");
    ok_eq_hex(Context->GetStatus, STATUS_SUCCESS);
    ok_eq_hex(Context->SetStatus, STATUS_SUCCESS);
    ok_eq_hex(Context->GetAgainStatus, STATUS_SUCCESS);
    if (NT_SUCCESS(Context->GetStatus))
        CheckNonVolatiles(&Reference, &Context->Read, "read on the new stack");
    if (NT_SUCCESS(Context->GetAgainStatus))
        CheckNonVolatiles(&Reference, &Context->ReadAgain, "read after the write");

    /* What the thread returns to user mode with */
    RtlZeroMemory(&Context->ReadAgain, sizeof(Context->ReadAgain));
    Context->ReadAgain.ContextFlags = CONTEXT_FULL;
    Status = PsGetContextThread(PsGetCurrentThread(), &Context->ReadAgain, KernelMode);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        CheckNonVolatiles(&Reference, &Context->ReadAgain, "read back on the original stack");

Cleanup:
    ExFreePoolWithTag(Context, TAG_CONTEXT_TEST);
}

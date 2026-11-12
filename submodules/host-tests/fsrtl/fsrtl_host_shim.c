/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Instrumented kernel primitives for the host build of oplock.c.
 *              Single-threaded model: a FAST_MUTEX released by a thread that does
 *              not own it aborts; a wait that is not yet satisfied runs the test's
 *              wait hook (standing in for the oplock holder's thread) and aborts if
 *              the hook did not satisfy it; completed IRPs get their list links
 *              poisoned (the I/O manager frees or reuses them) and freed pool is
 *              poisoned and quarantined, so a walk that follows a stale Flink
 *              faults instead of silently working.
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */
#include <ntoskrnl.h>
#include <stdio.h>
#include <stdlib.h>
#include "fsrtl_host.h"

#define POISON_BYTE 0xDB
#define POISON_PTR ((PLIST_ENTRY)(uintptr_t)0xDBDBDBDBDBDBDBDBull)

static KTHREAD HostThread;
KIRQL HostIrql = PASSIVE_LEVEL;
host_wait_hook HostWaitHook;
void *HostWaitHookContext;
int HostWaitCount;

static void HostFail(const char *What)
{
    fprintf(stderr, "FATAL (kernel contract): %s\n", What);
    fflush(stderr);
    abort();
}

PKTHREAD KeGetCurrentThread(void)
{
    return &HostThread;
}

/* Fast mutexes ------------------------------------------------------------ */
void ExInitializeFastMutex(PFAST_MUTEX Mutex)
{
    Mutex->Owner = NULL;
    Mutex->Acquired = 0;
    Mutex->OldIrql = PASSIVE_LEVEL;
}

void ExAcquireFastMutexUnsafe(PFAST_MUTEX Mutex)
{
    if (Mutex->Owner != NULL)
    {
        /* Single-threaded: an owned mutex can never be released while we block */
        HostFail(Mutex->Owner == &HostThread ? "fast mutex acquired recursively"
                                             : "fast mutex acquire would block forever");
    }
    Mutex->Owner = &HostThread;
    Mutex->Acquired++;
}

void ExReleaseFastMutexUnsafe(PFAST_MUTEX Mutex)
{
    if (Mutex->Owner != &HostThread)
    {
        HostFail("fast mutex released by a thread that does not own it (double release)");
    }
    Mutex->Owner = NULL;
}

void ExAcquireFastMutex(PFAST_MUTEX Mutex)
{
    KIRQL Old = HostIrql;
    if (Old > APC_LEVEL)
    {
        HostFail("ExAcquireFastMutex above APC_LEVEL");
    }
    HostIrql = APC_LEVEL;
    ExAcquireFastMutexUnsafe(Mutex);
    Mutex->OldIrql = Old;
}

void ExReleaseFastMutex(PFAST_MUTEX Mutex)
{
    KIRQL Old = Mutex->OldIrql;
    ExReleaseFastMutexUnsafe(Mutex);
    HostIrql = Old;
}

/* Events -------------------------------------------------------------------- */
void KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
    (void)Type;
    Event->Signaled = State;
}

LONG KeSetEvent(PKEVENT Event, LONG Increment, BOOLEAN Wait)
{
    LONG Previous = Event->Signaled;
    (void)Increment;
    (void)Wait;
    Event->Signaled = 1;
    return Previous;
}

NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON Reason, KPROCESSOR_MODE Mode,
                               BOOLEAN Alertable, PVOID Timeout)
{
    PKEVENT Event = Object;
    (void)Reason;
    (void)Mode;
    (void)Alertable;
    (void)Timeout;

    HostWaitCount++;
    if (!Event->Signaled && HostWaitHook != NULL)
    {
        /* The other thread (the oplock holder) runs while we are blocked */
        HostWaitHook(HostWaitHookContext);
    }
    if (!Event->Signaled)
    {
        HostFail("wait that nothing will ever satisfy (deadlock)");
    }
    return STATUS_SUCCESS;
}

/* Pool: poisoned and quarantined on free ------------------------------------ */
typedef struct _HOST_BLOCK
{
    struct _HOST_BLOCK *Next;
    size_t Size;
    int Freed;
    long long Align;
} HOST_BLOCK;
static HOST_BLOCK *HostBlocks;
int HostLiveAllocations;

PVOID ExAllocatePoolWithTag(int PoolType, size_t Size, ULONG Tag)
{
    HOST_BLOCK *Block;
    (void)PoolType;
    (void)Tag;
    Block = calloc(1, sizeof(*Block) + Size);
    if (Block == NULL)
    {
        HostFail("out of host memory");
    }
    Block->Size = Size;
    Block->Next = HostBlocks;
    HostBlocks = Block;
    HostLiveAllocations++;
    return Block + 1;
}

void ExFreePoolWithTag(PVOID P, ULONG Tag)
{
    HOST_BLOCK *Block = (HOST_BLOCK *)P - 1;
    (void)Tag;
    if (Block->Freed)
    {
        HostFail("pool block freed twice");
    }
    Block->Freed = 1;
    memset(P, POISON_BYTE, Block->Size);
    HostLiveAllocations--;
}

void HostReleaseQuarantine(void)
{
    while (HostBlocks != NULL)
    {
        HOST_BLOCK *Next = HostBlocks->Next;
        free(HostBlocks);
        HostBlocks = Next;
    }
    HostLiveAllocations = 0;
}

/* IRPs and objects ------------------------------------------------------------ */
void IoCompleteRequest(PIRP Irp, int PriorityBoost)
{
    (void)PriorityBoost;
    if (Irp->CompletionCount != 0)
    {
        HostFail("IRP completed twice");
    }
    Irp->CompletionCount++;
    Irp->FinalStatus = Irp->IoStatus;
    /* After completion the I/O manager owns (and frees) the IRP */
    Irp->Tail.Overlay.ListEntry.Flink = POISON_PTR;
    Irp->Tail.Overlay.ListEntry.Blink = POISON_PTR;
}

void IoAcquireCancelSpinLock(PKIRQL Irql)
{
    *Irql = HostIrql;
    HostIrql = DISPATCH_LEVEL;
}

void IoReleaseCancelSpinLock(KIRQL Irql)
{
    HostIrql = Irql;
}

PDRIVER_CANCEL IoSetCancelRoutine(PIRP Irp, PDRIVER_CANCEL CancelRoutine)
{
    PDRIVER_CANCEL Old = Irp->CancelRoutine;
    Irp->CancelRoutine = CancelRoutine;
    return Old;
}

void HostCancelIrp(PIRP Irp)
{
    PDRIVER_CANCEL Routine;
    IoAcquireCancelSpinLock(&Irp->CancelIrql);
    Irp->Cancel = TRUE;
    Routine = IoSetCancelRoutine(Irp, NULL);
    if (Routine == NULL)
    {
        IoReleaseCancelSpinLock(Irp->CancelIrql);
        return;
    }
    /* The cancel routine releases the cancel spin lock */
    Routine(NULL, Irp);
}

void ObReferenceObject(PVOID Object)
{
    ((PFILE_OBJECT)Object)->RefCount++;
}

void ObDereferenceObject(PVOID Object)
{
    PFILE_OBJECT FileObject = Object;
    if (FileObject->RefCount <= 0)
    {
        HostFail("FILE_OBJECT dereferenced below zero");
    }
    FileObject->RefCount--;
}

/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Oplock state machine (ntoskrnl/fsrtl/oplock.c, built unchanged):
 *              FsRtlCheckOplockEx flags, FsRtlOplockBreakH, FsRtlOplockIsSharedRequest
 *              (REMEDIATION-MATRIX-R2 M1-2) and the break/grant path defects fixed
 *              with them: double IntLock release, STATUS_SUCCESS for a pended IRP,
 *              list walks through freed elements, IRQL left raised by the
 *              exclusive-IRP cancel routine, acknowledge of an unbroken oplock.
 *              One case per process: `t_oplock <case>`; no argument runs them all.
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */
#include <ntoskrnl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fsrtl_host.h"

static int Failures;
#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            Failures++;                                                         \
        }                                                                       \
    } while (0)

/* IRP + its single stack location ----------------------------------------- */
typedef struct _HIRP
{
    IRP Irp;
    IO_STACK_LOCATION Stack;
    IO_SECURITY_CONTEXT Security;
    REQUEST_OPLOCK_INPUT_BUFFER Input;
} HIRP;

static void InitIrp(HIRP *H, UCHAR Major, PFILE_OBJECT FileObject)
{
    memset(H, 0, sizeof(*H));
    H->Irp.CurrentStack = &H->Stack;
    H->Stack.MajorFunction = Major;
    H->Stack.FileObject = FileObject;
}

static void InitCreate(HIRP *H, PFILE_OBJECT FileObject, ACCESS_MASK Access, ULONG Disposition, ULONG Options)
{
    InitIrp(H, IRP_MJ_CREATE, FileObject);
    H->Security.DesiredAccess = Access;
    H->Stack.Parameters.Create.SecurityContext = &H->Security;
    H->Stack.Parameters.Create.Options = (Disposition << 24) | Options;
    H->Stack.Parameters.Create.ShareAccess = FILE_SHARE_READ;
}

static void InitFsctl(HIRP *H, PFILE_OBJECT FileObject, ULONG Code)
{
    InitIrp(H, IRP_MJ_FILE_SYSTEM_CONTROL, FileObject);
    H->Stack.Parameters.FileSystemControl.FsControlCode = Code;
}

static NTSTATUS Grant(POPLOCK Oplock, HIRP *H, PFILE_OBJECT FileObject, ULONG Code)
{
    InitFsctl(H, FileObject, Code);
    /* OpenCount: 1 handle for the exclusive kinds, 0 byte-range locks for Level 2 */
    return FsRtlOplockFsctrl(Oplock, &H->Irp, Code == FSCTL_REQUEST_OPLOCK_LEVEL_2 ? 0 : 1);
}

static BOOLEAN BrokenTo(HIRP *H, ULONG_PTR Level)
{
    return H->Irp.CompletionCount == 1 && H->Irp.FinalStatus.Status == STATUS_SUCCESS &&
           H->Irp.FinalStatus.Information == Level;
}

/* Completion / pre-post routines of a posting file system ------------------- */
static int CompleteCalls, PrePostCalls;
static PIRP CompletedIrp;
static NTSTATUS CompletedStatus;

static void NTAPI OnComplete(PVOID Context, PIRP Irp)
{
    (void)Context;
    CompleteCalls++;
    CompletedIrp = Irp;
    CompletedStatus = Irp->IoStatus.Status;
}

static void NTAPI OnPrePost(PVOID Context, PIRP Irp)
{
    (void)Context;
    (void)Irp;
    PrePostCalls++;
}

/* The holder's thread: acknowledges the break while the breaker waits ------- */
typedef struct _ACK
{
    POPLOCK Oplock;
    PFILE_OBJECT Holder;
    ULONG Code;
    HIRP Irp;
    NTSTATUS Status;
    int Ran;
} ACK;

static void Acknowledge(void *Context)
{
    ACK *Ack = Context;
    Ack->Ran++;
    InitFsctl(&Ack->Irp, Ack->Holder, Ack->Code);
    Ack->Status = FsRtlOplockFsctrl(Ack->Oplock, &Ack->Irp.Irp, 1);
}

static void Reset(void)
{
    HostWaitHook = NULL;
    HostWaitHookContext = NULL;
    HostWaitCount = 0;
    HostIrql = PASSIVE_LEVEL;
    CompleteCalls = PrePostCalls = 0;
    CompletedIrp = NULL;
    CompletedStatus = -1;
}

static void Teardown(POPLOCK Oplock)
{
    FsRtlUninitializeOplock(Oplock);
    CHECK(HostLiveAllocations == 0);
    CHECK(HostIrql == PASSIVE_LEVEL);
    HostReleaseQuarantine();
}

/* ------------------------------------------------------------------------ */
/* M1-2: FsRtlCheckOplockEx flags                                              */
/* ------------------------------------------------------------------------ */

/* fastfat create, before the share check: a key check must never break or wait */
static void key_check_only_never_breaks(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Batch, Create;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_WRITE_DATA, FILE_OPEN, 0);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Create.Irp, OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 0);
    CHECK(Batch.Irp.CompletionCount == 0);
    CHECK(FsRtlCurrentBatchOplock(&Oplock));
    Teardown(&Oplock);
}

/* fastfat failed create: nothing atomic was granted, nothing to back out */
static void back_out_atomic_never_breaks(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Batch, Create;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_WRITE_DATA, FILE_OVERWRITE, 0);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Create.Irp, OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 0);
    CHECK(Batch.Irp.CompletionCount == 0);
    Teardown(&Oplock);
}

/* fastfat cleanup of a deleted child: break the parent's oplock, do not block,
 * do not run cleanup logic against the parent */
static void parent_object_breaks_without_blocking(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Parent = {0, 1}, Child = {0, 1};
    HIRP Batch, Cleanup;

    CHECK(Grant(&Oplock, &Batch, &Parent, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitIrp(&Cleanup, IRP_MJ_CLEANUP, &Child);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Cleanup.Irp,
                             OPLOCK_FLAG_PARENT_OBJECT | OPLOCK_FLAG_REMOVING_FILE_OR_LINK,
                             NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 0);
    CHECK(BrokenTo(&Batch, FILE_OPLOCK_BROKEN_TO_NONE));
    CHECK(Parent.RefCount == 2); /* the oplock's reference is kept until the ack */
    Teardown(&Oplock);
}

static void parent_object_breaks_level2(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Parent = {0, 1}, Child = {0, 1};
    HIRP Shared, Cleanup;

    CHECK(Grant(&Oplock, &Shared, &Parent, FSCTL_REQUEST_OPLOCK_LEVEL_2) == STATUS_PENDING);
    InitIrp(&Cleanup, IRP_MJ_CLEANUP, &Child);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Cleanup.Irp, OPLOCK_FLAG_PARENT_OBJECT, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 0);
    CHECK(BrokenTo(&Shared, FILE_OPLOCK_BROKEN_TO_NONE));
    CHECK(Parent.RefCount == 1);
    Teardown(&Oplock);
}

static void complete_if_oplocked_does_not_wait(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Writer = {0, 1};
    HIRP Batch, Write;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitIrp(&Write, IRP_MJ_WRITE, &Writer);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Write.Irp, OPLOCK_FLAG_COMPLETE_IF_OPLOCKED,
                             NULL, OnComplete, OnPrePost) == STATUS_OPLOCK_BREAK_IN_PROGRESS);
    CHECK(HostWaitCount == 0);
    CHECK(!Write.Irp.PendingReturned);
    CHECK(PrePostCalls == 0 && CompleteCalls == 0);
    CHECK(BrokenTo(&Batch, FILE_OPLOCK_BROKEN_TO_NONE));
    Teardown(&Oplock);
}

static void open_requiring_oplock_cannot_break(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Batch, Create;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_WRITE_DATA, FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK);
    CHECK(FsRtlCheckOplockEx(&Oplock, &Create.Irp, 0, NULL, NULL, NULL) == STATUS_CANNOT_BREAK_OPLOCK);
    CHECK(HostWaitCount == 0);
    CHECK(Batch.Irp.CompletionCount == 0);
    Teardown(&Oplock);
}

/* Regression guard: the classic entry point keeps its create classification */
static void classic_read_only_create_does_not_break(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Batch, Create;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_READ_DATA, FILE_OPEN, 0);
    CHECK(FsRtlCheckOplock(&Oplock, &Create.Irp, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(Batch.Irp.CompletionCount == 0);
    Teardown(&Oplock);
}

/* ------------------------------------------------------------------------ */
/* M1-2: FsRtlOplockBreakH                                                     */
/* ------------------------------------------------------------------------ */

/* fastfat create sharing violation, read-only opener: the Batch holder must be
 * broken so it closes its cached handle; the create is posted */
static void break_h_batch_posts_and_resumes_on_ack(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Batch, Create;
    ACK Ack;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_READ_DATA, FILE_OPEN, 0);
    CHECK(FsRtlOplockBreakH(&Oplock, &Create.Irp, 0, NULL, OnComplete, OnPrePost) == STATUS_PENDING);
    CHECK(Create.Irp.PendingReturned);
    CHECK(PrePostCalls == 1 && CompleteCalls == 0);
    CHECK(BrokenTo(&Batch, FILE_OPLOCK_BROKEN_TO_NONE));

    memset(&Ack, 0, sizeof(Ack));
    Ack.Oplock = &Oplock;
    Ack.Holder = &Holder;
    Ack.Code = FSCTL_OPLOCK_BREAK_ACK_NO_2;
    Acknowledge(&Ack);
    CHECK(Ack.Status == STATUS_SUCCESS);
    CHECK(CompleteCalls == 1 && CompletedIrp == &Create.Irp && CompletedStatus == STATUS_SUCCESS);
    CHECK(Holder.RefCount == 1);
    CHECK(!FsRtlCurrentBatchOplock(&Oplock));
    Teardown(&Oplock);
}

static void break_h_filter_waits_for_ack(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Filter, Create;
    ACK Ack;

    CHECK(Grant(&Oplock, &Filter, &Holder, FSCTL_REQUEST_FILTER_OPLOCK) == STATUS_PENDING);
    memset(&Ack, 0, sizeof(Ack));
    Ack.Oplock = &Oplock;
    Ack.Holder = &Holder;
    Ack.Code = FSCTL_OPLOCK_BREAK_ACK_NO_2;
    HostWaitHook = Acknowledge;
    HostWaitHookContext = &Ack;
    InitCreate(&Create, &Opener, FILE_READ_DATA, FILE_OPEN, 0);
    CHECK(FsRtlOplockBreakH(&Oplock, &Create.Irp, 0, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 1 && Ack.Ran == 1);
    CHECK(BrokenTo(&Filter, FILE_OPLOCK_BROKEN_TO_NONE));
    Teardown(&Oplock);
}

/* Level 1 and Level 2 cache no handle: nothing to break */
static void break_h_leaves_level1(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Level1, Create;

    CHECK(Grant(&Oplock, &Level1, &Holder, FSCTL_REQUEST_OPLOCK_LEVEL_1) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_WRITE_DATA, FILE_OPEN, 0);
    CHECK(FsRtlOplockBreakH(&Oplock, &Create.Irp, 0, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 0);
    CHECK(Level1.Irp.CompletionCount == 0);
    Teardown(&Oplock);
}

static void break_h_leaves_level2(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Opener = {0, 1};
    HIRP Shared, Create;

    CHECK(Grant(&Oplock, &Shared, &Holder, FSCTL_REQUEST_OPLOCK_LEVEL_2) == STATUS_PENDING);
    InitCreate(&Create, &Opener, FILE_WRITE_DATA, FILE_OPEN, 0);
    CHECK(FsRtlOplockBreakH(&Oplock, &Create.Irp, 0, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(Shared.Irp.CompletionCount == 0);
    Teardown(&Oplock);
}

/* ------------------------------------------------------------------------ */
/* FsRtlOplockIsSharedRequest                                                  */
/* ------------------------------------------------------------------------ */
static void is_shared_request(void)
{
    FILE_OBJECT Fo = {0, 1};
    HIRP H;

    InitFsctl(&H, &Fo, FSCTL_REQUEST_OPLOCK_LEVEL_2);
    CHECK(FsRtlOplockIsSharedRequest(&H.Irp));
    InitFsctl(&H, &Fo, FSCTL_REQUEST_OPLOCK_LEVEL_1);
    CHECK(!FsRtlOplockIsSharedRequest(&H.Irp));
    InitFsctl(&H, &Fo, FSCTL_REQUEST_BATCH_OPLOCK);
    CHECK(!FsRtlOplockIsSharedRequest(&H.Irp));

    InitFsctl(&H, &Fo, FSCTL_REQUEST_OPLOCK);
    H.Irp.AssociatedIrp.SystemBuffer = &H.Input;
    H.Stack.Parameters.FileSystemControl.InputBufferLength = sizeof(H.Input);
    H.Input.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
    H.Input.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    CHECK(FsRtlOplockIsSharedRequest(&H.Irp));
    H.Input.RequestedOplockLevel |= OPLOCK_LEVEL_CACHE_WRITE;
    CHECK(!FsRtlOplockIsSharedRequest(&H.Irp));
    H.Input.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ;
    H.Stack.Parameters.FileSystemControl.InputBufferLength = sizeof(H.Input) - 1;
    CHECK(!FsRtlOplockIsSharedRequest(&H.Irp));

    InitIrp(&H, IRP_MJ_WRITE, &Fo);
    CHECK(!FsRtlOplockIsSharedRequest(&H.Irp));
}

/* ------------------------------------------------------------------------ */
/* Break and grant path defects (D1-D6)                                        */
/* ------------------------------------------------------------------------ */

/* D1: synchronous break; IntLock was released twice after the wait */
static void sync_break_releases_lock_once(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Writer = {0, 1};
    HIRP Batch, Write;
    ACK Ack;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    memset(&Ack, 0, sizeof(Ack));
    Ack.Oplock = &Oplock;
    Ack.Holder = &Holder;
    Ack.Code = FSCTL_OPLOCK_BREAK_ACK_NO_2;
    HostWaitHook = Acknowledge;
    HostWaitHookContext = &Ack;
    InitIrp(&Write, IRP_MJ_WRITE, &Writer);
    CHECK(FsRtlCheckOplock(&Oplock, &Write.Irp, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(HostWaitCount == 1 && Ack.Ran == 1 && Ack.Status == STATUS_SUCCESS);
    CHECK(BrokenTo(&Batch, FILE_OPLOCK_BROKEN_TO_NONE));
    Teardown(&Oplock);
}

/* D2: a posted IRP must be reported as STATUS_PENDING */
static void posted_break_returns_pending(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, Writer = {0, 1};
    HIRP Batch, Write;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitIrp(&Write, IRP_MJ_WRITE, &Writer);
    CHECK(FsRtlCheckOplock(&Oplock, &Write.Irp, NULL, OnComplete, OnPrePost) == STATUS_PENDING);
    CHECK(Write.Irp.PendingReturned && PrePostCalls == 1 && CompleteCalls == 0);
    Teardown(&Oplock);
    CHECK(CompleteCalls == 1); /* uninitialize releases the waiter */
}

/* D3: the shared list walk completes each Level 2 IRP and then read its link */
static void break_level2_with_two_holders(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT HolderA = {0, 1}, HolderB = {0, 1}, Writer = {0, 1};
    HIRP SharedA, SharedB, Write;

    CHECK(Grant(&Oplock, &SharedA, &HolderA, FSCTL_REQUEST_OPLOCK_LEVEL_2) == STATUS_PENDING);
    CHECK(Grant(&Oplock, &SharedB, &HolderB, FSCTL_REQUEST_OPLOCK_LEVEL_2) == STATUS_PENDING);
    InitIrp(&Write, IRP_MJ_WRITE, &Writer);
    CHECK(FsRtlCheckOplock(&Oplock, &Write.Irp, NULL, NULL, NULL) == STATUS_SUCCESS);
    CHECK(BrokenTo(&SharedA, FILE_OPLOCK_BROKEN_TO_NONE));
    CHECK(BrokenTo(&SharedB, FILE_OPLOCK_BROKEN_TO_NONE));
    CHECK(HolderA.RefCount == 1 && HolderB.RefCount == 1);
    Teardown(&Oplock);
}

/* D3: the wait list walk freed each WAIT_CONTEXT and then read its link */
static void ack_releases_two_waiters(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1}, WriterA = {0, 1}, WriterB = {0, 1};
    HIRP Batch, WriteA, WriteB;
    ACK Ack;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    InitIrp(&WriteA, IRP_MJ_WRITE, &WriterA);
    InitIrp(&WriteB, IRP_MJ_WRITE, &WriterB);
    CHECK(FsRtlCheckOplock(&Oplock, &WriteA.Irp, NULL, OnComplete, NULL) == STATUS_PENDING);
    CHECK(FsRtlCheckOplock(&Oplock, &WriteB.Irp, NULL, OnComplete, NULL) == STATUS_PENDING);
    memset(&Ack, 0, sizeof(Ack));
    Ack.Oplock = &Oplock;
    Ack.Holder = &Holder;
    Ack.Code = FSCTL_OPLOCK_BREAK_ACK_NO_2;
    Acknowledge(&Ack);
    CHECK(Ack.Status == STATUS_SUCCESS);
    CHECK(CompleteCalls == 2);
    Teardown(&Oplock);
}

/* D4: cancelling the granted exclusive IRP must not leave the IRQL raised */
static void cancel_exclusive_restores_irql(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1};
    HIRP Batch;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    HostCancelIrp(&Batch.Irp);
    CHECK(Batch.Irp.CompletionCount == 1 && Batch.Irp.FinalStatus.Status == STATUS_CANCELLED);
    CHECK(HostIrql == PASSIVE_LEVEL);
    CHECK(Holder.RefCount == 1);
    CHECK(!FsRtlCurrentBatchOplock(&Oplock));
    Teardown(&Oplock);
}

/* D5: every granted oplock IRP stays queued: STATUS_PENDING */
static void grant_returns_pending(void)
{
    OPLOCK Oplock = NULL, Oplock2 = NULL;
    FILE_OBJECT Holder = {0, 1}, Holder2 = {0, 1};
    HIRP Batch, Shared;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    CHECK(Batch.Irp.PendingReturned && Batch.Irp.CompletionCount == 0);
    CHECK(Grant(&Oplock2, &Shared, &Holder2, FSCTL_REQUEST_OPLOCK_LEVEL_2) == STATUS_PENDING);
    CHECK(Shared.Irp.PendingReturned && Shared.Irp.CompletionCount == 0);
    FsRtlUninitializeOplock(&Oplock2);
    Teardown(&Oplock);
}

/* D6: acknowledging an oplock that was never broken is a protocol error and
 * must not drop the holder's reference */
static void stray_ack_is_rejected(void)
{
    OPLOCK Oplock = NULL;
    FILE_OBJECT Holder = {0, 1};
    HIRP Batch;
    ACK Ack;

    CHECK(Grant(&Oplock, &Batch, &Holder, FSCTL_REQUEST_BATCH_OPLOCK) == STATUS_PENDING);
    memset(&Ack, 0, sizeof(Ack));
    Ack.Oplock = &Oplock;
    Ack.Holder = &Holder;
    Ack.Code = FSCTL_OPLOCK_BREAK_ACK_NO_2;
    Acknowledge(&Ack);
    CHECK(Ack.Status == STATUS_INVALID_OPLOCK_PROTOCOL);
    CHECK(Ack.Irp.Irp.CompletionCount == 1);
    CHECK(Batch.Irp.CompletionCount == 0);
    CHECK(Holder.RefCount == 2);
    CHECK(FsRtlCurrentBatchOplock(&Oplock));
    Teardown(&Oplock);
}

/* ------------------------------------------------------------------------ */
static const struct
{
    const char *Name;
    void (*Run)(void);
} Cases[] = {
    { "key_check_only_never_breaks", key_check_only_never_breaks },
    { "back_out_atomic_never_breaks", back_out_atomic_never_breaks },
    { "parent_object_breaks_without_blocking", parent_object_breaks_without_blocking },
    { "parent_object_breaks_level2", parent_object_breaks_level2 },
    { "complete_if_oplocked_does_not_wait", complete_if_oplocked_does_not_wait },
    { "open_requiring_oplock_cannot_break", open_requiring_oplock_cannot_break },
    { "classic_read_only_create_does_not_break", classic_read_only_create_does_not_break },
    { "break_h_batch_posts_and_resumes_on_ack", break_h_batch_posts_and_resumes_on_ack },
    { "break_h_filter_waits_for_ack", break_h_filter_waits_for_ack },
    { "break_h_leaves_level1", break_h_leaves_level1 },
    { "break_h_leaves_level2", break_h_leaves_level2 },
    { "is_shared_request", is_shared_request },
    { "sync_break_releases_lock_once", sync_break_releases_lock_once },
    { "posted_break_returns_pending", posted_break_returns_pending },
    { "break_level2_with_two_holders", break_level2_with_two_holders },
    { "ack_releases_two_waiters", ack_releases_two_waiters },
    { "cancel_exclusive_restores_irql", cancel_exclusive_restores_irql },
    { "grant_returns_pending", grant_returns_pending },
    { "stray_ack_is_rejected", stray_ack_is_rejected },
};

int main(int argc, char **argv)
{
    size_t i;
    int Ran = 0, Failed = 0;

    for (i = 0; i < sizeof(Cases) / sizeof(Cases[0]); i++)
    {
        int Before = Failures;
        if (argc > 1 && strcmp(argv[1], Cases[i].Name) != 0)
        {
            continue;
        }
        Reset();
        Cases[i].Run();
        Ran++;
        if (Failures != Before)
        {
            Failed++;
        }
        printf("%s %s\n", Failures != Before ? "FAIL" : "ok  ", Cases[i].Name);
    }

    if (Ran == 0)
    {
        fprintf(stderr, "unknown case %s\n", argc > 1 ? argv[1] : "");
        return 2;
    }
    printf("%d case(s), %d failed\n", Ran, Failed);
    return Failed ? 1 : 0;
}

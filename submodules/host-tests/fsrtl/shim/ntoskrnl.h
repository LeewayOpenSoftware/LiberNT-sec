/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Minimal kernel surface that ntoskrnl/fsrtl/oplock.c compiles against
 *              on a host. Found through -I ahead of the real headers, so the real
 *              oplock.c is built unchanged. The primitives are instrumented: a
 *              FAST_MUTEX aborts on a release by a non-owner, completed IRPs and freed
 *              pool are poisoned, IRQL is tracked, and a wait that would block runs
 *              the test's hook (the thread that would satisfy it) or aborts.
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */
#ifndef FSRTL_HOST_NTOSKRNL_H
#define FSRTL_HOST_NTOSKRNL_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

/* Basic types ------------------------------------------------------------ */
#define IN
#define OUT
#define OPTIONAL
#define NTAPI
#define VOID void
typedef void *PVOID;
typedef unsigned char UCHAR, BOOLEAN, *PBOOLEAN, KIRQL, *PKIRQL;
typedef unsigned short USHORT;
typedef uint32_t ULONG, *PULONG, ACCESS_MASK;
typedef int32_t LONG, NTSTATUS;
typedef uintptr_t ULONG_PTR;
#define TRUE 1
#define FALSE 0

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - offsetof(type, field)))
#define BooleanFlagOn(F, SF) ((BOOLEAN)(((F) & (SF)) != 0))
#define FlagOn(F, SF) ((F) & (SF))
#define SetFlag(F, SF) ((F) |= (SF))
#define ClearFlag(F, SF) ((F) &= ~(SF))

#define PAGED_CODE() do { } while (0)
#define ASSERT(x) assert(x)

/* Lists ------------------------------------------------------------------ */
typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

static inline void InitializeListHead(PLIST_ENTRY Head)
{
    Head->Flink = Head->Blink = Head;
}
static inline BOOLEAN IsListEmpty(const LIST_ENTRY *Head)
{
    return (BOOLEAN)(Head->Flink == Head);
}
static inline BOOLEAN RemoveEntryList(PLIST_ENTRY Entry)
{
    PLIST_ENTRY Flink = Entry->Flink, Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}
static inline void InsertTailList(PLIST_ENTRY Head, PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink = Head->Blink;
    Entry->Flink = Head;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    Head->Blink = Entry;
}
static inline void InsertHeadList(PLIST_ENTRY Head, PLIST_ENTRY Entry)
{
    PLIST_ENTRY Flink = Head->Flink;
    Entry->Flink = Flink;
    Entry->Blink = Head;
    Flink->Blink = Entry;
    Head->Flink = Entry;
}

/* Status codes ----------------------------------------------------------- */
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000)
#define STATUS_PENDING                   ((NTSTATUS)0x00000103)
#define STATUS_OPLOCK_BREAK_IN_PROGRESS  ((NTSTATUS)0x00000108)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000D)
#define STATUS_CANCELLED                 ((NTSTATUS)0xC0000120)
#define STATUS_OPLOCK_NOT_GRANTED        ((NTSTATUS)0xC00000E2)
#define STATUS_INVALID_OPLOCK_PROTOCOL   ((NTSTATUS)0xC00000E3)
#define STATUS_CANNOT_BREAK_OPLOCK       ((NTSTATUS)0xC0000909)

/* Threads, IRQL, fast mutexes, events ------------------------------------ */
typedef struct _KTHREAD { int Dummy; } KTHREAD, *PKTHREAD;
#define PASSIVE_LEVEL  0
#define APC_LEVEL      1
#define DISPATCH_LEVEL 2

typedef struct _FAST_MUTEX
{
    PKTHREAD Owner;
    KIRQL OldIrql;
    LONG Acquired;
} FAST_MUTEX, *PFAST_MUTEX;

typedef struct _KEVENT
{
    LONG Signaled;
} KEVENT, *PKEVENT;

typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;
typedef enum _KWAIT_REASON { Executive } KWAIT_REASON;
typedef enum _MODE { KernelMode, UserMode } KPROCESSOR_MODE;

PKTHREAD KeGetCurrentThread(void);
void ExInitializeFastMutex(PFAST_MUTEX Mutex);
void ExAcquireFastMutexUnsafe(PFAST_MUTEX Mutex);
void ExReleaseFastMutexUnsafe(PFAST_MUTEX Mutex);
void ExAcquireFastMutex(PFAST_MUTEX Mutex);
void ExReleaseFastMutex(PFAST_MUTEX Mutex);
void KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, BOOLEAN State);
LONG KeSetEvent(PKEVENT Event, LONG Increment, BOOLEAN Wait);
NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON Reason, KPROCESSOR_MODE Mode,
                               BOOLEAN Alertable, PVOID Timeout);

/* Pool ------------------------------------------------------------------- */
typedef enum _POOL_TYPE { NonPagedPool = 0, PagedPool = 1 } POOL_TYPE;
#define POOL_COLD_ALLOCATION 256
#define POOL_RAISE_IF_ALLOCATION_FAILURE 16
#define TAG_OPLOCK 'orSF'
PVOID ExAllocatePoolWithTag(int PoolType, size_t Size, ULONG Tag);
void ExFreePoolWithTag(PVOID P, ULONG Tag);
#define RtlZeroMemory(Dst, Len) memset((Dst), 0, (Len))
#include <string.h>

/* SEH: nothing raises in these tests (allocation never fails) ------------- */
#define _SEH2_TRY {
#define _SEH2_FINALLY } {
#define _SEH2_END }
#define _SEH2_AbnormalTermination() 0

/* Objects and IRPs ------------------------------------------------------- */
typedef struct _DEVICE_OBJECT { int Dummy; } DEVICE_OBJECT, *PDEVICE_OBJECT;

#define FO_CLEANUP_COMPLETE 0x00004000
typedef struct _FILE_OBJECT
{
    ULONG Flags;
    LONG RefCount;      /* host: ObReference/ObDereference balance */
} FILE_OBJECT, *PFILE_OBJECT;

typedef enum _FILE_INFORMATION_CLASS
{
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileShortNameInformation = 40,
} FILE_INFORMATION_CLASS;

typedef struct _IO_SECURITY_CONTEXT
{
    ACCESS_MASK DesiredAccess;
} IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;

typedef struct _IO_STACK_LOCATION
{
    UCHAR MajorFunction;
    PFILE_OBJECT FileObject;
    union
    {
        struct
        {
            PIO_SECURITY_CONTEXT SecurityContext;
            ULONG Options;
            USHORT FileAttributes;
            USHORT ShareAccess;
        } Create;
        struct
        {
            ULONG OutputBufferLength;
            ULONG InputBufferLength;
            ULONG FsControlCode;
        } FileSystemControl;
        struct
        {
            FILE_INFORMATION_CLASS FileInformationClass;
            BOOLEAN AdvanceOnly;
        } SetFile;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

struct _IRP;
typedef void (NTAPI *PDRIVER_CANCEL)(PDEVICE_OBJECT DeviceObject, struct _IRP *Irp);

typedef struct _IO_STATUS_BLOCK
{
    NTSTATUS Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

#define IRP_PAGING_IO             0x00000002
#define IRP_SYNCHRONOUS_PAGING_IO 0x00000040

typedef struct _IRP
{
    ULONG Flags;
    IO_STATUS_BLOCK IoStatus;
    BOOLEAN Cancel;
    KIRQL CancelIrql;
    PDRIVER_CANCEL CancelRoutine;
    union { PVOID SystemBuffer; } AssociatedIrp;
    struct { struct { LIST_ENTRY ListEntry; } Overlay; } Tail;
    /* host bookkeeping */
    PIO_STACK_LOCATION CurrentStack;
    BOOLEAN Synchronous;
    BOOLEAN PendingReturned;
    int CompletionCount;
    IO_STATUS_BLOCK FinalStatus;
} IRP, *PIRP;

#define IO_NO_INCREMENT   0
#define IO_DISK_INCREMENT 1

static inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp)
{
    return Irp->CurrentStack;
}
static inline void IoMarkIrpPending(PIRP Irp)
{
    Irp->PendingReturned = TRUE;
}
static inline BOOLEAN IoIsOperationSynchronous(PIRP Irp)
{
    return Irp->Synchronous;
}
void IoCompleteRequest(PIRP Irp, int PriorityBoost);
#define IofCompleteRequest IoCompleteRequest
void IoAcquireCancelSpinLock(PKIRQL Irql);
void IoReleaseCancelSpinLock(KIRQL Irql);
PDRIVER_CANCEL IoSetCancelRoutine(PIRP Irp, PDRIVER_CANCEL CancelRoutine);
void ObReferenceObject(PVOID Object);
void ObDereferenceObject(PVOID Object);

/* Access, share, create options, FSCTLs ---------------------------------- */
#define FILE_READ_DATA        0x0001
#define FILE_WRITE_DATA       0x0002
#define FILE_READ_EA          0x0008
#define FILE_EXECUTE          0x0020
#define FILE_READ_ATTRIBUTES  0x0080
#define FILE_WRITE_ATTRIBUTES 0x0100
#define READ_CONTROL          0x00020000
#define SYNCHRONIZE           0x00100000
#define FILE_SHARE_READ       0x00000001
#define FILE_SHARE_WRITE      0x00000002
#define FILE_SHARE_DELETE     0x00000004
#define FILE_SHARE_VALID_FLAGS 0x00000007
#define FILE_OPEN             0x00000001
#define FILE_OVERWRITE        0x00000004
#define FILE_OVERWRITE_IF     0x00000005
#define FILE_COMPLETE_IF_OPLOCKED  0x00000100
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_RESERVE_OPFILTER      0x00100000

#define IRP_MJ_CREATE              0x00
#define IRP_MJ_READ                0x03
#define IRP_MJ_WRITE               0x04
#define IRP_MJ_SET_INFORMATION     0x06
#define IRP_MJ_FLUSH_BUFFERS       0x09
#define IRP_MJ_FILE_SYSTEM_CONTROL 0x0d
#define IRP_MJ_LOCK_CONTROL        0x11
#define IRP_MJ_CLEANUP             0x12

#define CTL_CODE(t, f, m, a) (((t) << 16) | ((a) << 14) | ((f) << 2) | (m))
#define FSCTL_FS(f, a) CTL_CODE(0x00000009, (f), 0, (a))
#define FSCTL_REQUEST_OPLOCK_LEVEL_1    FSCTL_FS(0, 0)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2    FSCTL_FS(1, 0)
#define FSCTL_REQUEST_BATCH_OPLOCK      FSCTL_FS(2, 0)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE  FSCTL_FS(3, 0)
#define FSCTL_OPBATCH_ACK_CLOSE_PENDING FSCTL_FS(4, 0)
#define FSCTL_OPLOCK_BREAK_NOTIFY       FSCTL_FS(5, 0)
#define FSCTL_OPLOCK_BREAK_ACK_NO_2     FSCTL_FS(20, 0)
#define FSCTL_REQUEST_FILTER_OPLOCK     FSCTL_FS(23, 0)
#define FSCTL_SET_ZERO_DATA             FSCTL_FS(50, 2)
#define FSCTL_REQUEST_OPLOCK            FSCTL_FS(144, 0)

#define FILE_OPLOCK_BROKEN_TO_LEVEL_2 0x00000007
#define FILE_OPLOCK_BROKEN_TO_NONE    0x00000008

#define OPLOCK_LEVEL_CACHE_READ   0x00000001
#define OPLOCK_LEVEL_CACHE_HANDLE 0x00000002
#define OPLOCK_LEVEL_CACHE_WRITE  0x00000004
#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST 0x00000001
typedef struct _REQUEST_OPLOCK_INPUT_BUFFER
{
    USHORT StructureVersion;
    USHORT StructureLength;
    ULONG RequestedOplockLevel;
    ULONG Flags;
} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

#define OPLOCK_FLAG_COMPLETE_IF_OPLOCKED    0x00000001
#define OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY   0x00000002
#define OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK  0x00000004
#define OPLOCK_FLAG_IGNORE_OPLOCK_KEYS      0x00000008
#define OPLOCK_FLAG_PARENT_OBJECT           0x00000010
#define OPLOCK_FLAG_CLOSING_DELETE_ON_CLOSE 0x00000020
#define OPLOCK_FLAG_REMOVING_FILE_OR_LINK   0x00000040

/* FsRtl oplock API (as ntifs.h declares it) ------------------------------ */
typedef PVOID OPLOCK, *POPLOCK;
typedef void (NTAPI *POPLOCK_WAIT_COMPLETE_ROUTINE)(PVOID Context, PIRP Irp);
typedef void (NTAPI *POPLOCK_FS_PREPOST_IRP)(PVOID Context, PIRP Irp);

void NTAPI FsRtlInitializeOplock(POPLOCK Oplock);
void NTAPI FsRtlUninitializeOplock(POPLOCK Oplock);
NTSTATUS NTAPI FsRtlOplockFsctrl(POPLOCK Oplock, PIRP Irp, ULONG OpenCount);
NTSTATUS NTAPI FsRtlCheckOplock(POPLOCK Oplock, PIRP Irp, PVOID Context,
                                POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
                                POPLOCK_FS_PREPOST_IRP PostIrpRoutine);
NTSTATUS NTAPI FsRtlCheckOplockEx(POPLOCK Oplock, PIRP Irp, ULONG Flags, PVOID Context,
                                  POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
                                  POPLOCK_FS_PREPOST_IRP PostIrpRoutine);
NTSTATUS NTAPI FsRtlOplockBreakH(POPLOCK Oplock, PIRP Irp, ULONG Flags, PVOID Context,
                                 POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
                                 POPLOCK_FS_PREPOST_IRP PostIrpRoutine);
BOOLEAN NTAPI FsRtlOplockIsSharedRequest(PIRP Irp);
BOOLEAN NTAPI FsRtlCurrentBatchOplock(POPLOCK Oplock);
BOOLEAN NTAPI FsRtlOplockIsFastIoPossible(POPLOCK Oplock);

#endif /* FSRTL_HOST_NTOSKRNL_H */

/*
 * PROJECT:     NetIO driver
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Network store (NSI): provider registry, table access and change requests
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <ntifs.h>
#include <netiodef.h>
#include <nsikm.h>

#define TAG_NSI 'tSsN'

typedef struct _NSI_PROVIDER
{
    LIST_ENTRY ListEntry;
    NPI_MODULEID Module;
    ULONG Table;
    NSI_PROVIDER_DISPATCH Dispatch;
    PVOID Context;
    volatile LONG References;
    BOOLEAN Deregistering;
    KEVENT Released;
    IO_CSQ Csq;
    LIST_ENTRY PendingIrps;
    KSPIN_LOCK PendingLock;
} NSI_PROVIDER;

static LIST_ENTRY NsiProviderList;
static KSPIN_LOCK NsiProviderLock;
/* Deregistered providers are kept here for the life of the system: see NsiDeregisterProvider. */
static LIST_ENTRY NsiZombieList;
static BOOLEAN NsiReady;

/* How many change requests may wait on one provider: from one file object, and
 * in all. A requester keeps one per registration, so the first limit is far
 * above honest use; the second bounds the memory and the walks of the queue */
#define NSI_MAX_PENDING_PER_FILE 64
#define NSI_MAX_PENDING_PER_PROVIDER 4096

static IO_CSQ_INSERT_IRP_EX NsiCsqInsertIrp;
static IO_CSQ_REMOVE_IRP NsiCsqRemoveIrp;
static IO_CSQ_PEEK_NEXT_IRP NsiCsqPeekNextIrp;
static IO_CSQ_ACQUIRE_LOCK NsiCsqAcquireLock;
static IO_CSQ_RELEASE_LOCK NsiCsqReleaseLock;
static IO_CSQ_COMPLETE_CANCELED_IRP NsiCsqCompleteCanceledIrp;

VOID
NsiInitialize(VOID)
{
    InitializeListHead(&NsiProviderList);
    InitializeListHead(&NsiZombieList);
    KeInitializeSpinLock(&NsiProviderLock);
    NsiReady = TRUE;
}

static BOOLEAN
NsiModuleEqual(
    _In_ const NPI_MODULEID *First,
    _In_ const NPI_MODULEID *Second)
{
    if (First->Type != Second->Type)
        return FALSE;
    if (First->Type == MIT_GUID)
        return RtlEqualMemory(&First->Guid, &Second->Guid, sizeof(GUID));
    if (First->Type == MIT_IF_LUID)
        return First->IfLuid.LowPart == Second->IfLuid.LowPart &&
               First->IfLuid.HighPart == Second->IfLuid.HighPart;
    return FALSE;
}

static PNSI_PROVIDER
NsiFindProviderLocked(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table)
{
    PLIST_ENTRY Entry;

    for (Entry = NsiProviderList.Flink; Entry != &NsiProviderList; Entry = Entry->Flink)
    {
        PNSI_PROVIDER Provider = CONTAINING_RECORD(Entry, NSI_PROVIDER, ListEntry);

        if (Provider->Table == Table && !Provider->Deregistering &&
            NsiModuleEqual(&Provider->Module, Module))
        {
            return Provider;
        }
    }
    return NULL;
}

static PNSI_PROVIDER
NsiReferenceProvider(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table)
{
    PNSI_PROVIDER Provider;
    KIRQL OldIrql;

    if (!NsiReady || Module == NULL)
        return NULL;
    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    Provider = NsiFindProviderLocked(Module, Table);
    if (Provider != NULL)
        InterlockedIncrement(&Provider->References);
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);
    return Provider;
}

static VOID
NsiDereferenceProvider(
    _In_ PNSI_PROVIDER Provider)
{
    if (InterlockedDecrement(&Provider->References) == 0)
        KeSetEvent(&Provider->Released, IO_NO_INCREMENT, FALSE);
}

static BOOLEAN
NsiReferenceRegisteredProvider(
    _In_ PNSI_PROVIDER Provider)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;

    if (!NsiReady)
        return FALSE;
    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    for (Entry = NsiProviderList.Flink; Entry != &NsiProviderList; Entry = Entry->Flink)
    {
        if (CONTAINING_RECORD(Entry, NSI_PROVIDER, ListEntry) != Provider)
            continue;
        if (!Provider->Deregistering)
        {
            InterlockedIncrement(&Provider->References);
            Found = TRUE;
        }
        break;
    }
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);
    return Found;
}

static NTSTATUS
NsiCheckSizes(
    _In_ const NSI_PROVIDER *Provider,
    _In_ const NSI_ROW_SIZES *Sizes)
{
    const NSI_ROW_SIZES *Own = &Provider->Dispatch.RowSizes;

    if ((Sizes->Key != 0 && Sizes->Key != Own->Key) ||
        (Sizes->Rw != 0 && Sizes->Rw != Own->Rw) ||
        (Sizes->Dynamic != 0 && Sizes->Dynamic != Own->Dynamic) ||
        (Sizes->Static != 0 && Sizes->Static != Own->Static))
    {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* Called with the queue lock held: the count and the insertion are one step */
static NTSTATUS NTAPI
NsiCsqInsertIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp,
    _In_ PVOID InsertContext)
{
    PNSI_PROVIDER Provider = CONTAINING_RECORD(Csq, NSI_PROVIDER, Csq);
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PLIST_ENTRY Entry;
    ULONG Total = 0, SameFile = 0;

    UNREFERENCED_PARAMETER(InsertContext);

    for (Entry = Provider->PendingIrps.Flink; Entry != &Provider->PendingIrps; Entry = Entry->Flink)
    {
        PIRP Queued = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        Total++;
        if (IoGetCurrentIrpStackLocation(Queued)->FileObject == FileObject)
            SameFile++;
    }
    if (Total >= NSI_MAX_PENDING_PER_PROVIDER || SameFile >= NSI_MAX_PENDING_PER_FILE)
        return STATUS_QUOTA_EXCEEDED;

    InsertTailList(&Provider->PendingIrps, &Irp->Tail.Overlay.ListEntry);
    return STATUS_SUCCESS;
}

static VOID NTAPI
NsiCsqRemoveIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static PIRP NTAPI
NsiCsqPeekNextIrp(
    _In_ PIO_CSQ Csq,
    _In_opt_ PIRP Irp,
    _In_opt_ PVOID PeekContext)
{
    PNSI_PROVIDER Provider = CONTAINING_RECORD(Csq, NSI_PROVIDER, Csq);
    PLIST_ENTRY Entry;

    Entry = (Irp == NULL) ? Provider->PendingIrps.Flink : Irp->Tail.Overlay.ListEntry.Flink;
    for (; Entry != &Provider->PendingIrps; Entry = Entry->Flink)
    {
        PIRP Candidate = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        /* PeekContext is a provider-owner key: a PFILE_OBJECT (handle cleanup) or a
         * PDEVICE_OBJECT (driver unload). A file-object pointer and a device-object
         * pointer never alias, so matching either serves both callers without a tag. */
        if (PeekContext == NULL ||
            IoGetCurrentIrpStackLocation(Candidate)->FileObject == (PFILE_OBJECT)PeekContext ||
            IoGetCurrentIrpStackLocation(Candidate)->DeviceObject == (PDEVICE_OBJECT)PeekContext)
        {
            return Candidate;
        }
    }
    return NULL;
}

_IRQL_raises_(DISPATCH_LEVEL)
static VOID NTAPI
NsiCsqAcquireLock(
    _In_ PIO_CSQ Csq,
    _Out_ PKIRQL Irql)
{
    PNSI_PROVIDER Provider = CONTAINING_RECORD(Csq, NSI_PROVIDER, Csq);

    KeAcquireSpinLock(&Provider->PendingLock, Irql);
}

static VOID NTAPI
NsiCsqReleaseLock(
    _In_ PIO_CSQ Csq,
    _In_ KIRQL Irql)
{
    PNSI_PROVIDER Provider = CONTAINING_RECORD(Csq, NSI_PROVIDER, Csq);

    KeReleaseSpinLock(&Provider->PendingLock, Irql);
}

static VOID NTAPI
NsiCsqCompleteCanceledIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* Move the queued requests of Owner (all of them if Owner is NULL) to Taken, in
 * one walk of the queue. This is IoCsqRemoveNextIrp for many requests at once:
 * that call starts its search at the head of the queue for every request it
 * removes. A request whose cancel routine is already gone is being cancelled:
 * its cancel routine takes it off the queue and completes it, it is left alone */
static VOID
NsiTakePendingIrps(
    _In_ PNSI_PROVIDER Provider,
    _In_opt_ PVOID Owner,
    _Inout_ PLIST_ENTRY Taken)
{
    PLIST_ENTRY Entry, Next;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Provider->PendingLock, &OldIrql);
    for (Entry = Provider->PendingIrps.Flink; Entry != &Provider->PendingIrps; Entry = Next)
    {
        PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        Next = Entry->Flink;
        if (Owner != NULL &&
            IoGetCurrentIrpStackLocation(Irp)->FileObject != (PFILE_OBJECT)Owner &&
            IoGetCurrentIrpStackLocation(Irp)->DeviceObject != (PDEVICE_OBJECT)Owner)
        {
            continue;
        }
        if (IoSetCancelRoutine(Irp, NULL) == NULL)
            continue;
        RemoveEntryList(Entry);
        Irp->Tail.Overlay.DriverContext[3] = NULL;
        InsertTailList(Taken, Entry);
    }
    KeReleaseSpinLock(&Provider->PendingLock, OldIrql);
}

static VOID
NsiDrainPendingIrps(
    _In_ PNSI_PROVIDER Provider,
    _In_opt_ PFILE_OBJECT FileObject,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information)
{
    LIST_ENTRY Drained;
    PLIST_ENTRY Entry;
    PIRP Irp;

    /* Take the requests that are queued now, then complete them. A requester
     * that is woken by its completion asks again at once, and on one processor
     * it runs before this thread does: a loop that looked at the queue again
     * after every completion found that new request, completed it too, and so
     * never ended. A request that arrives after this point is for the next
     * change */
    InitializeListHead(&Drained);
    NsiTakePendingIrps(Provider, FileObject, &Drained);

    while (!IsListEmpty(&Drained))
    {
        Entry = RemoveHeadList(&Drained);
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = Information;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
}

NTSTATUS
NTAPI
NsiRegisterProvider(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _In_ const NSI_PROVIDER_DISPATCH *Dispatch,
    _In_opt_ PVOID Context,
    _Out_ PNSI_PROVIDER *Provider)
{
    PNSI_PROVIDER New;
    KIRQL OldIrql;
    NTSTATUS Status;

    *Provider = NULL;
    if (!NsiReady)
        return STATUS_DEVICE_NOT_READY;
    if (Module == NULL || Dispatch == NULL || Dispatch->Size < sizeof(*Dispatch) ||
        Dispatch->GetAll == NULL || (Dispatch->RowSizes.Key == 0 && Dispatch->Enumerate != NULL))
    {
        /* A table without a key has one row: it can be read, not enumerated */
        return STATUS_INVALID_PARAMETER;
    }
    New = ExAllocatePoolWithTag(NonPagedPool, sizeof(*New), TAG_NSI);
    if (New == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(New, sizeof(*New));
    New->Module = *Module;
    New->Table = Table;
    RtlCopyMemory(&New->Dispatch, Dispatch, sizeof(New->Dispatch));
    New->Context = Context;
    New->References = 1;
    KeInitializeEvent(&New->Released, NotificationEvent, FALSE);
    InitializeListHead(&New->PendingIrps);
    KeInitializeSpinLock(&New->PendingLock);
    Status = IoCsqInitializeEx(&New->Csq, NsiCsqInsertIrp, NsiCsqRemoveIrp, NsiCsqPeekNextIrp,
                             NsiCsqAcquireLock, NsiCsqReleaseLock, NsiCsqCompleteCanceledIrp);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(New, TAG_NSI);
        return Status;
    }

    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    if (NsiFindProviderLocked(Module, Table) != NULL)
    {
        KeReleaseSpinLock(&NsiProviderLock, OldIrql);
        ExFreePoolWithTag(New, TAG_NSI);
        return STATUS_OBJECT_NAME_COLLISION;
    }
    InsertTailList(&NsiProviderList, &New->ListEntry);
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);

    *Provider = New;
    return STATUS_SUCCESS;
}

VOID
NTAPI
NsiDeregisterProvider(
    _In_ PNSI_PROVIDER Provider)
{
    KIRQL OldIrql;

    PAGED_CODE();

    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    Provider->Deregistering = TRUE;
    RemoveEntryList(&Provider->ListEntry);
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);

    NsiDereferenceProvider(Provider);
    KeWaitForSingleObject(&Provider->Released, Executive, KernelMode, FALSE, NULL);
    NsiDrainPendingIrps(Provider, NULL, STATUS_CANCELLED, 0);

    /* Do not free the provider. The CSQ library contract is that the queue object
     * outlives every IRP ever queued on it: a cancel routine reaches the embedded Csq
     * through the IRP and calls our lock and completion callbacks after it released
     * the cancel spin lock, and it holds no reference on the provider. So the provider
     * must stay valid until the last such call returns. It is kept on a list for the
     * life of the system; providers register their tables once per boot. */
    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    InsertTailList(&NsiZombieList, &Provider->ListEntry);
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);
}

VOID
NTAPI
NsiNotifyChange(
    _In_ PNSI_PROVIDER Provider,
    _In_ NSI_CHANGE_TYPE Type,
    _In_reads_bytes_opt_(KeySize) const VOID *Key,
    _In_ ULONG KeySize)
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (!NsiReferenceRegisteredProvider(Provider))
        return;
    /* The request has no output: the completion itself is the news */
    NsiDrainPendingIrps(Provider, NULL, STATUS_SUCCESS, 0);
    NsiDereferenceProvider(Provider);
}

NTSTATUS
NTAPI
NsiRequestChangeNotificationKm(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _In_ PIRP Irp)
{
    PNSI_PROVIDER Provider = NsiReferenceProvider(Module, Table);
    NTSTATUS Status;

    if (Provider == NULL)
        return STATUS_NOT_FOUND;
    /* The queue marks the request pending, also when it then refuses it */
    Status = IoCsqInsertIrpEx(&Provider->Csq, Irp, NULL, NULL);
    NsiDereferenceProvider(Provider);
    if (!NT_SUCCESS(Status))
    {
        /* Not queued: the caller completes it, so it must not look pending */
        IoGetCurrentIrpStackLocation(Irp)->Control &= ~SL_PENDING_RETURNED;
        return Status;
    }
    return STATUS_PENDING;
}

/* Cancel every queued change-notification IRP whose owner matches Owner: a
 * PFILE_OBJECT (handle cleanup) or a PDEVICE_OBJECT (driver unload). Removal is
 * cancel-safe (NsiTakePendingIrps); the IRPs are completed only after both the
 * provider and the queue locks are dropped, so a caller completion routine cannot
 * re-enter NSI under NsiProviderLock. */
static VOID
NsiCancelChangeNotificationsByOwner(
    _In_opt_ PVOID Owner)
{
    LIST_ENTRY Cancelled;
    PLIST_ENTRY Entry;
    PIRP Irp;
    KIRQL OldIrql;

    if (!NsiReady)
        return;
    InitializeListHead(&Cancelled);
    KeAcquireSpinLock(&NsiProviderLock, &OldIrql);
    for (Entry = NsiProviderList.Flink; Entry != &NsiProviderList; Entry = Entry->Flink)
    {
        PNSI_PROVIDER Provider = CONTAINING_RECORD(Entry, NSI_PROVIDER, ListEntry);

        NsiTakePendingIrps(Provider, Owner, &Cancelled);
    }
    KeReleaseSpinLock(&NsiProviderLock, OldIrql);

    while (!IsListEmpty(&Cancelled))
    {
        Entry = RemoveHeadList(&Cancelled);
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
}

VOID
NTAPI
NsiCancelChangeNotificationsKm(
    _In_ PFILE_OBJECT FileObject)
{
    NsiCancelChangeNotificationsByOwner(FileObject);
}

/* Lets nsiproxy drain its own queued notification IRPs by device object on unload,
 * before IoDeleteDevice, without a per-IRP completion routine (a top-level pended IRP
 * has no stack location for one). The store owns and completes these IRPs. */
VOID
NTAPI
NsiCancelChangeNotificationsByDeviceKm(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    NsiCancelChangeNotificationsByOwner(DeviceObject);
}

NTSTATUS
NTAPI
NsiQueryTableSizesKm(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _Out_ PNSI_ROW_SIZES Sizes)
{
    PNSI_PROVIDER Provider = NsiReferenceProvider(Module, Table);

    RtlZeroMemory(Sizes, sizeof(*Sizes));
    if (Provider == NULL)
        return STATUS_NOT_FOUND;
    *Sizes = Provider->Dispatch.RowSizes;
    NsiDereferenceProvider(Provider);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NsiEnumerateAllParametersKm(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _In_ const NSI_ROW_SIZES *Sizes,
    _Inout_ PNSI_ENUMERATE_REQUEST Request)
{
    PNSI_PROVIDER Provider = NsiReferenceProvider(Module, Table);
    NTSTATUS Status;

    if (Provider == NULL)
        return STATUS_NOT_FOUND;
    Status = NsiCheckSizes(Provider, Sizes);
    if (NT_SUCCESS(Status))
    {
        if (Provider->Dispatch.Enumerate == NULL)
            Status = STATUS_NOT_SUPPORTED;
        else
            Status = Provider->Dispatch.Enumerate(Provider->Context, Request);
    }
    NsiDereferenceProvider(Provider);
    return Status;
}

NTSTATUS
NTAPI
NsiGetAllParametersKm(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _In_ const NSI_ROW_SIZES *Sizes,
    _In_ ULONG FirstArg,
    _In_reads_bytes_(KeySize) const VOID *Key,
    _In_ ULONG KeySize,
    _Out_writes_bytes_opt_(Sizes->Rw) PVOID Rw,
    _Out_writes_bytes_opt_(Sizes->Dynamic) PVOID Dynamic,
    _Out_writes_bytes_opt_(Sizes->Static) PVOID Static)
{
    PNSI_PROVIDER Provider = NsiReferenceProvider(Module, Table);
    NTSTATUS Status;

    if (Provider == NULL)
        return STATUS_NOT_FOUND;
    Status = NsiCheckSizes(Provider, Sizes);
    if (NT_SUCCESS(Status) && KeySize != Provider->Dispatch.RowSizes.Key)
        Status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(Status))
    {
        Status = Provider->Dispatch.GetAll(Provider->Context, FirstArg, Key, KeySize,
                                           Sizes->Rw ? Rw : NULL,
                                           Sizes->Dynamic ? Dynamic : NULL,
                                           Sizes->Static ? Static : NULL);
    }
    NsiDereferenceProvider(Provider);
    return Status;
}

static NTSTATUS
NsiGetParameterFromRow(
    _In_ PNSI_PROVIDER Provider,
    _In_ ULONG FirstArg,
    _In_reads_bytes_(KeySize) const VOID *Key,
    _In_ ULONG KeySize,
    _In_ ULONG ParamType,
    _In_ ULONG DataOffset,
    _Out_writes_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize)
{
    const NSI_ROW_SIZES *Own = &Provider->Dispatch.RowSizes;
    ULONG SectionSize;
    PVOID Row;
    NTSTATUS Status;

    switch (ParamType)
    {
        case NSI_PARAM_RW: SectionSize = Own->Rw; break;
        case NSI_PARAM_DYNAMIC: SectionSize = Own->Dynamic; break;
        case NSI_PARAM_STATIC: SectionSize = Own->Static; break;
        default: return STATUS_INVALID_PARAMETER;
    }
    if (SectionSize == 0 || DataOffset > SectionSize || DataSize > SectionSize - DataOffset)
        return STATUS_INVALID_PARAMETER;
    Row = ExAllocatePoolWithTag(NonPagedPool, SectionSize, TAG_NSI);
    if (Row == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Row, SectionSize);
    Status = Provider->Dispatch.GetAll(Provider->Context, FirstArg, Key, KeySize,
                                       ParamType == NSI_PARAM_RW ? Row : NULL,
                                       ParamType == NSI_PARAM_DYNAMIC ? Row : NULL,
                                       ParamType == NSI_PARAM_STATIC ? Row : NULL);
    if (NT_SUCCESS(Status))
        RtlCopyMemory(Data, (PUCHAR)Row + DataOffset, DataSize);
    ExFreePoolWithTag(Row, TAG_NSI);
    return Status;
}

NTSTATUS
NTAPI
NsiGetParameterKm(
    _In_ const NPI_MODULEID *Module,
    _In_ ULONG Table,
    _In_ ULONG FirstArg,
    _In_reads_bytes_(KeySize) const VOID *Key,
    _In_ ULONG KeySize,
    _In_ ULONG ParamType,
    _In_ ULONG DataOffset,
    _Out_writes_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize)
{
    PNSI_PROVIDER Provider = NsiReferenceProvider(Module, Table);
    NTSTATUS Status;

    if (Provider == NULL)
        return STATUS_NOT_FOUND;
    if (KeySize != Provider->Dispatch.RowSizes.Key)
    {
        Status = STATUS_INVALID_PARAMETER;
    }
    else if (Provider->Dispatch.GetParameter != NULL)
    {
        Status = Provider->Dispatch.GetParameter(Provider->Context, FirstArg, Key, KeySize,
                                                 ParamType, DataOffset, Data, DataSize);
    }
    else
    {
        Status = NsiGetParameterFromRow(Provider, FirstArg, Key, KeySize,
                                        ParamType, DataOffset, Data, DataSize);
    }
    NsiDereferenceProvider(Provider);
    return Status;
}

/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test-side controls of the instrumented kernel shim (fsrtl_host_shim.c).
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */
#ifndef FSRTL_HOST_H
#define FSRTL_HOST_H

typedef void (*host_wait_hook)(void *Context);

/* Current tracked IRQL (raised by ExAcquireFastMutex and the cancel spin lock) */
extern KIRQL HostIrql;
/* Runs when a wait is not yet satisfied: the thread that would satisfy it */
extern host_wait_hook HostWaitHook;
extern void *HostWaitHookContext;
/* Number of KeWaitForSingleObject calls */
extern int HostWaitCount;
/* Pool blocks allocated and not freed */
extern int HostLiveAllocations;

/* IoCancelIrp: set Cancel and run the cancel routine under the cancel spin lock */
void HostCancelIrp(PIRP Irp);
/* Really free the poisoned (quarantined) pool blocks */
void HostReleaseQuarantine(void);

#endif /* FSRTL_HOST_H */

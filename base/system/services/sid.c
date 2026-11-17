/*
 * PROJECT:     LiberNT Services Control Manager
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NT SERVICE\<name> SID of a service
 * COPYRIGHT:   Copyright 2026 Leeway Open Software <281492504+LeewayOpenSoftware@users.noreply.github.com>
 */

#include "services.h"

#include <ntstatus.h>
#include <reactos/servicesid.h>

/* Allocate (HeapAlloc) the service SID of a service name; free with HeapFree. */
DWORD
ScmGetServiceSid(
    _In_ PCWSTR pszServiceName,
    _Out_ PSID *ppSid)
{
    PSID pSid;
    NTSTATUS Status;

    *ppSid = NULL;
    pSid = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LSA_SERVICE_SID_LENGTH);
    if (pSid == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Status = LsaFmtServiceSid(pszServiceName, (ULONG)wcslen(pszServiceName), pSid);
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GetProcessHeap(), 0, pSid);
        return ERROR_INVALID_NAME;
    }

    *ppSid = pSid;
    return ERROR_SUCCESS;
}

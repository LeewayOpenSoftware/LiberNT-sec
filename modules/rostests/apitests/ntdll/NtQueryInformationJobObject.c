/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NtQueryInformationJobObject
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

/* Every byte of the returned structure is the kernel's to define: no kernel stack in the padding */
static
VOID
CheckGap(
    _In_ const UCHAR *Bytes,
    _In_ ULONG From,
    _In_ ULONG To,
    _In_ PCSTR Where)
{
    ULONG i;

    for (i = From; i < To; i++)
    {
        ok(Bytes[i] == 0, "%s: byte 0x%02x at offset %lu is not zero\n", Where, Bytes[i], i);
    }
}

static
VOID
CheckBasicLimitPadding(
    _In_ const UCHAR *Bytes,
    _In_ PCSTR Where)
{
    CheckGap(Bytes,
             FIELD_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, LimitFlags) + sizeof(ULONG),
             FIELD_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, MinimumWorkingSetSize),
             Where);
    CheckGap(Bytes,
             FIELD_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, ActiveProcessLimit) + sizeof(ULONG),
             FIELD_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, Affinity),
             Where);
}

START_TEST(NtQueryInformationJobObject)
{
    union
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION Extended;
        UCHAR Bytes[sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)];
    } Limits;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Job;
    ULONG Length;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtCreateJobObject(&Job, JOB_OBJECT_ALL_ACCESS, &ObjectAttributes);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("No job object\n");
        return;
    }

    RtlFillMemory(&Limits, sizeof(Limits), 0xCC);
    Length = 0;
    Status = NtQueryInformationJobObject(Job,
                                         JobObjectBasicLimitInformation,
                                         &Limits,
                                         sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION),
                                         &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Length == sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION), "Basic limit length %lu\n", Length);
    if (NT_SUCCESS(Status))
    {
        ok(Limits.Extended.BasicLimitInformation.LimitFlags == 0, "New job has limit flags 0x%lx\n",
           Limits.Extended.BasicLimitInformation.LimitFlags);
        CheckBasicLimitPadding(Limits.Bytes, "basic");
    }

    RtlFillMemory(&Limits, sizeof(Limits), 0xCC);
    Length = 0;
    Status = NtQueryInformationJobObject(Job,
                                         JobObjectExtendedLimitInformation,
                                         &Limits,
                                         sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
                                         &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Length == sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION), "Extended limit length %lu\n", Length);
    if (NT_SUCCESS(Status))
    {
        CheckBasicLimitPadding(Limits.Bytes, "extended");
        ok(Limits.Extended.IoInfo.ReadOperationCount == 0 && Limits.Extended.IoInfo.WriteOperationCount == 0,
           "IoInfo of the extended limits is not zero\n");
        ok(Limits.Extended.PeakJobMemoryUsed == 0, "Peak job memory %Iu for a new job\n",
           Limits.Extended.PeakJobMemoryUsed);
    }

    NtClose(Job);
}

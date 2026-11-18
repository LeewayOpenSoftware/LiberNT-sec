/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     A processor feature reported as available can be used
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

#ifdef _M_AMD64

typedef ULONG64 (*PREAD_GS_BASE)(VOID);

static
VOID
TestReadGsBase(VOID)
{
    static const UCHAR Code[] = { 0xF3, 0x48, 0x0F, 0xAE, 0xC8, 0xC3 };
    BOOLEAN Available = SharedUserData->ProcessorFeatures[PF_RDWRFSGSBASE_AVAILABLE];
    BOOLEAN Faulted = FALSE;
    PVOID Base = NULL;
    SIZE_T Size = sizeof(Code);
    ULONG64 Value = 0;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("No executable memory\n");
        return;
    }
    RtlCopyMemory(Base, Code, sizeof(Code));

    _SEH2_TRY
    {
        Value = ((PREAD_GS_BASE)Base)();
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;

    ok(Faulted == !Available, "PF_RDWRFSGSBASE_AVAILABLE is %u but RDGSBASE %s\n",
       Available, Faulted ? "faults" : "executes");
    if (!Faulted)
        ok(Value == (ULONG64)(ULONG_PTR)NtCurrentTeb(), "RDGSBASE returned 0x%I64x, the TEB is at %p\n", Value, NtCurrentTeb());

    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
}

#endif

START_TEST(ProcessorFeatures)
{
#ifdef _M_AMD64
    TestReadGsBase();
#else
    skip("No processor feature check for this architecture\n");
#endif
}

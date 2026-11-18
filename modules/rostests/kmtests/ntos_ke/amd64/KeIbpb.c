/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     IBPB (IA32_PRED_CMD) capability detection and barrier write are consistent and safe
 * COPYRIGHT:   Copyright 2026 LeewayOpenSoftware
 */

#include <kmt_test.h>

#define CPUID7_EDX_IBRS_IBPB  (1u << 26)
#define CPUID8_EBX_IBPB       (1u << 12)
#define IA32_PRED_CMD         0x0049
#define PRED_CMD_IBPB_BIT     1

static
BOOLEAN
KmtCpuSupportsIbpb(VOID)
{
    int Regs[4];
    BOOLEAN Ibpb = FALSE;
    CHAR Vendor[13];

    __cpuid(Regs, 0);
    *(int *)&Vendor[0] = Regs[1];
    *(int *)&Vendor[4] = Regs[3];
    *(int *)&Vendor[8] = Regs[2];
    Vendor[12] = ANSI_NULL;

    if ((unsigned int)Regs[0] >= 7)
    {
        __cpuidex(Regs, 7, 0);
        if (Regs[3] & CPUID7_EDX_IBRS_IBPB)
            Ibpb = TRUE;
    }

    if (strcmp(Vendor, "AuthenticAMD") == 0 || strcmp(Vendor, "HygonGenuine") == 0)
    {
        __cpuid(Regs, 0x80000000);
        if ((unsigned int)Regs[0] >= 0x80000008)
        {
            __cpuid(Regs, 0x80000008);
            if (Regs[1] & CPUID8_EBX_IBPB)
                Ibpb = TRUE;
        }
    }

    return Ibpb;
}

START_TEST(KeIbpb)
{
    KAFFINITY ActiveProcessors;
    ULONG Index;
    LONG FirstState = -1;

    ActiveProcessors = KeQueryActiveProcessors();

    for (Index = 0; Index < sizeof(KAFFINITY) * 8; Index++)
    {
        KAFFINITY Mask = (KAFFINITY)1 << Index;
        KAFFINITY OldAffinity;
        BOOLEAN Supported;
        BOOLEAN Faulted = FALSE;

        if ((ActiveProcessors & Mask) == 0)
            continue;

        OldAffinity = KeSetSystemAffinityThreadEx(Mask);

        Supported = KmtCpuSupportsIbpb();
        if (Supported)
        {
            _SEH2_TRY
            {
                __writemsr(IA32_PRED_CMD, PRED_CMD_IBPB_BIT);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Faulted = TRUE;
            }
            _SEH2_END;
        }

        KeRevertToUserAffinityThreadEx(OldAffinity);

        if (Supported)
            ok(!Faulted, "CPU %lu: PRED_CMD write faulted though CPUID reports IBPB\n", Index);

        if (FirstState < 0)
            FirstState = Supported ? 1 : 0;
        else
            ok((LONG)(Supported ? 1 : 0) == FirstState,
               "CPU %lu: IBPB support=%d disagrees with CPU0 (%ld)\n", Index, Supported, FirstState);

        trace("CPU %lu: IBPB supported=%d\n", Index, Supported);
    }

    ok(FirstState >= 0, "No active processor was tested\n");
}

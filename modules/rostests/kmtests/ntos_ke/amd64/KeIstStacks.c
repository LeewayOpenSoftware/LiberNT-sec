/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     amd64 double fault, machine check and NMI each have their own stack on every processor
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>

#define IST_TEST_CPUS 64
#define IST_TEST_STACKS 4

#define IST_TEST_GATES 3

C_ASSERT(IST_TEST_CPUS == sizeof(KAFFINITY) * 8);

typedef struct _IST_RECORD
{
    ULONG64 Top[IST_TEST_CPUS][IST_TEST_STACKS];
    UCHAR GateIst[IST_TEST_CPUS][IST_TEST_GATES];
    LONG Calls;
} IST_RECORD, *PIST_RECORD;

static const PCSTR IstNames[IST_TEST_STACKS] = { "double fault", "machine check", "NMI", "DPC" };
static const ULONG64 IstSizes[IST_TEST_STACKS] =
{
    DOUBLE_FAULT_STACK_SIZE, DOUBLE_FAULT_STACK_SIZE, DOUBLE_FAULT_STACK_SIZE, KERNEL_STACK_SIZE
};
static const UCHAR IstGateVectors[IST_TEST_GATES] = { 8, 18, 2 };

static
ULONG_PTR
NTAPI
IstIpiWorker(
    _In_ ULONG_PTR Argument)
{
    PIST_RECORD Record = (PIST_RECORD)Argument;
    ULONG Cpu = KeGetCurrentProcessorNumber();
    PKTSS64 Tss = KeGetPcr()->TssBase;
    ULONG Gate;

    if (Cpu < IST_TEST_CPUS)
    {
        Record->Top[Cpu][0] = Tss->Ist[1];
        Record->Top[Cpu][1] = Tss->Ist[2];
        Record->Top[Cpu][2] = Tss->Ist[3];
        /* The first DPC stack of the boot processor is the double-fault stack until KiInitializeKernel replaces it */
        Record->Top[Cpu][3] = (ULONG64)KeGetCurrentPrcb()->DpcStack;
        for (Gate = 0; Gate < IST_TEST_GATES; Gate++)
            Record->GateIst[Cpu][Gate] = (UCHAR)KeGetPcr()->IdtBase[IstGateVectors[Gate]].IstIndex;
        InterlockedIncrement(&Record->Calls);
    }
    return 0;
}

static
BOOLEAN
IstApart(
    _In_ ULONG64 FirstTop,
    _In_ ULONG64 FirstSize,
    _In_ ULONG64 SecondTop,
    _In_ ULONG64 SecondSize)
{
    if (FirstTop > SecondTop)
        return FirstTop - SecondTop >= FirstSize;

    return SecondTop - FirstTop >= SecondSize;
}

START_TEST(KeIstStacks)
{
    PIST_RECORD Record;
    ULONG Cpu, Other, Stack, OtherStack, Gate, Count = 0;

    Record = ExAllocatePoolZero(NonPagedPool, sizeof(*Record), 'tsIK');
    if (skip(Record != NULL, "No memory for the record\n"))
        return;

    KeIpiGenericCall(IstIpiWorker, (ULONG_PTR)Record);
    ok(Record->Calls >= 1, "The worker ran on %ld processors\n", Record->Calls);

    for (Cpu = 0; Cpu < IST_TEST_CPUS; Cpu++)
    {
        if (Record->Top[Cpu][0] == 0 && Record->Top[Cpu][1] == 0 && Record->Top[Cpu][2] == 0)
            continue;
        Count++;

        for (Gate = 0; Gate < IST_TEST_GATES; Gate++)
        {
            ok(Record->GateIst[Cpu][Gate] == Gate + 1, "Processor %lu: vector %u uses IST %u, expected %lu\n",
               Cpu, IstGateVectors[Gate], Record->GateIst[Cpu][Gate], Gate + 1);
        }

        for (Stack = 0; Stack < IST_TEST_STACKS; Stack++)
        {
            ok(Record->Top[Cpu][Stack] != 0, "Processor %lu has no %s stack\n", Cpu, IstNames[Stack]);
            ok((Record->Top[Cpu][Stack] & 0xF) == 0, "Processor %lu: %s stack top 0x%I64x is not aligned\n",
               Cpu, IstNames[Stack], Record->Top[Cpu][Stack]);

            for (Other = Cpu; Other < IST_TEST_CPUS; Other++)
            {
                for (OtherStack = (Other == Cpu) ? Stack + 1 : 0; OtherStack < IST_TEST_STACKS; OtherStack++)
                {
                    if (Record->Top[Other][OtherStack] == 0)
                        continue;
                    ok(IstApart(Record->Top[Cpu][Stack], IstSizes[Stack],
                                Record->Top[Other][OtherStack], IstSizes[OtherStack]),
                       "Processor %lu %s stack 0x%I64x overlaps processor %lu %s stack 0x%I64x\n",
                       Cpu, IstNames[Stack], Record->Top[Cpu][Stack],
                       Other, IstNames[OtherStack], Record->Top[Other][OtherStack]);
                }
            }
        }
    }

    ok(Count == (ULONG)Record->Calls, "Recorded %lu processors, the worker ran on %ld\n", Count, Record->Calls);
    ExFreePoolWithTag(Record, 'tsIK');
}

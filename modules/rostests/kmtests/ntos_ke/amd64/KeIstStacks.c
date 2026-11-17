/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     amd64 double fault, machine check and NMI each have their own stack on every processor
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>

#define IST_TEST_CPUS 64
#define IST_TEST_STACKS 4

typedef struct _IST_RECORD
{
    ULONG64 Top[IST_TEST_CPUS][IST_TEST_STACKS];
    LONG Calls;
} IST_RECORD, *PIST_RECORD;

static const PCSTR IstNames[IST_TEST_STACKS] = { "double fault", "machine check", "NMI", "DPC" };

static
ULONG_PTR
NTAPI
IstIpiWorker(
    _In_ ULONG_PTR Argument)
{
    PIST_RECORD Record = (PIST_RECORD)Argument;
    ULONG Cpu = KeGetCurrentProcessorNumber();
    PKTSS64 Tss = KeGetPcr()->TssBase;

    if (Cpu < IST_TEST_CPUS)
    {
        Record->Top[Cpu][0] = Tss->Ist[1];
        Record->Top[Cpu][1] = Tss->Ist[2];
        Record->Top[Cpu][2] = Tss->Ist[3];
        Record->Top[Cpu][3] = (ULONG64)KeGetCurrentPrcb()->DpcStack;
    }
    InterlockedIncrement(&Record->Calls);
    return 0;
}

static
BOOLEAN
IstApart(
    _In_ ULONG64 First,
    _In_ ULONG64 Second)
{
    ULONG64 Distance = (First > Second) ? First - Second : Second - First;

    return Distance >= KERNEL_STACK_SIZE;
}

START_TEST(KeIstStacks)
{
    PIST_RECORD Record;
    ULONG Cpu, Other, Stack, OtherStack, Count = 0;

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
                    ok(IstApart(Record->Top[Cpu][Stack], Record->Top[Other][OtherStack]),
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

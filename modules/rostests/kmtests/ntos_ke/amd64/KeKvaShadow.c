/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     amd64 kernel VA shadow transitions are either complete or absent, the same on every processor
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>

#define KVA_TEST_CPUS 64
#define KVA_TEST_STUB_SIZE 16
#define KVA_TEST_GATES 256

C_ASSERT(KVA_TEST_CPUS == sizeof(KAFFINITY) * 8);

typedef struct _KVA_CPU_RECORD
{
    ULONG Seen;
    ULONG Active;
    ULONG PlainGates;
    ULONG StubGates;
    ULONG BadGateFields;
    ULONG MissingHandlers;
    ULONG UnexpectedIstGates;
    ULONG IstGatesInStubTable;
    ULONG ExitPointerSet;
    ULONG Rsp0IsTransitionTop;
    ULONG64 Lstar;
    ULONG64 Cstar;
} KVA_CPU_RECORD, *PKVA_CPU_RECORD;

typedef struct _KVA_RECORD
{
    KVA_CPU_RECORD Cpu[KVA_TEST_CPUS];
    LONG Calls;
} KVA_RECORD, *PKVA_RECORD;

static
ULONG64
KvaGateOffset(
    _In_ PKIDTENTRY64 Gate)
{
    return (ULONG64)Gate->OffsetHigh << 32 | (ULONG64)Gate->OffsetMiddle << 16 | (ULONG64)Gate->OffsetLow;
}

static
ULONG_PTR
NTAPI
KvaIpiWorker(
    _In_ ULONG_PTR Argument)
{
    PKVA_RECORD Record = (PKVA_RECORD)Argument;
    PKIPCR Pcr = (PKIPCR)KeGetPcr();
    PKIDTENTRY64 Idt = Pcr->IdtBase;
    PKVA_CPU_RECORD Cpu;
    ULONG64 Base, Offset, Handler;
    ULONG Index;

    if (Pcr->Prcb.Number >= KVA_TEST_CPUS)
        return 0;

    Cpu = &Record->Cpu[Pcr->Prcb.Number];
    Base = KvaGateOffset(&Idt[0]);
    Cpu->Active = (Pcr->KvaShadow.ShadowFlags & KVA_SHADOW_ACTIVE) != 0;

    for (Index = 0; Index < KVA_TEST_GATES; Index++)
    {
        Offset = KvaGateOffset(&Idt[Index]);
        if (Idt[Index].IstIndex != 0)
        {
            if (Index != 2 && Index != 8 && Index != 18)
                Cpu->UnexpectedIstGates++;
            if (Offset >= Base && Offset < Base + KVA_TEST_GATES * KVA_TEST_STUB_SIZE)
                Cpu->IstGatesInStubTable++;
            continue;
        }

        Cpu->PlainGates++;
        if (Offset == Base + Index * KVA_TEST_STUB_SIZE)
            Cpu->StubGates++;
        if (Idt[Index].Type != 0x0e || !Idt[Index].Present || Idt[Index].Selector != KGDT64_R0_CODE)
            Cpu->BadGateFields++;

        Handler = (ULONG64)Pcr->KvaShadowHandlers[Index];
        if (Handler == 0 || (Handler >= Base && Handler < Base + KVA_TEST_GATES * KVA_TEST_STUB_SIZE))
            Cpu->MissingHandlers++;
    }

    Cpu->ExitPointerSet = Pcr->KvaShadowExitIretq != NULL;
    Cpu->Rsp0IsTransitionTop =
        Pcr->TssBase->Rsp0 == (ULONG64)&Pcr->KvaShadowTransitionStack[sizeof(Pcr->KvaShadowTransitionStack)];
    Cpu->Lstar = __readmsr(MSR_LSTAR);
    Cpu->Cstar = __readmsr(MSR_CSTAR);
    Cpu->Seen = TRUE;
    InterlockedIncrement(&Record->Calls);
    return 0;
}

START_TEST(KeKvaShadow)
{
    PKVA_RECORD Record;
    PKVA_CPU_RECORD Cpu, First = NULL;
    ULONG Number, Count = 0;

    Record = ExAllocatePoolZero(NonPagedPool, sizeof(*Record), 'tvKK');
    if (skip(Record != NULL, "No memory for the record\n"))
        return;

    KeIpiGenericCall(KvaIpiWorker, (ULONG_PTR)Record);
    ok(Record->Calls >= 1, "The worker ran on %ld processors\n", Record->Calls);

    for (Number = 0; Number < KVA_TEST_CPUS; Number++)
    {
        Cpu = &Record->Cpu[Number];
        if (!Cpu->Seen)
            continue;
        Count++;
        if (First == NULL)
            First = Cpu;

        /* The lab gate reads this line from the debug port to know the mode each processor really runs in */
        DbgPrint("KVA shadow transitions: processor %lu active %lu\n", Number, Cpu->Active);

        ok(Cpu->Active == First->Active, "Processor %lu: active %lu, the first processor has %lu\n",
           Number, Cpu->Active, First->Active);
        ok(Cpu->Lstar != 0 && Cpu->Lstar == First->Lstar, "Processor %lu: LSTAR 0x%I64x, the first processor has 0x%I64x\n",
           Number, Cpu->Lstar, First->Lstar);
        ok(Cpu->Cstar == First->Cstar, "Processor %lu: CSTAR 0x%I64x, the first processor has 0x%I64x\n",
           Number, Cpu->Cstar, First->Cstar);
        ok(Cpu->UnexpectedIstGates == 0, "Processor %lu: %lu gates other than 2, 8 and 18 use an IST\n",
           Number, Cpu->UnexpectedIstGates);
        ok(Cpu->BadGateFields == 0, "Processor %lu: %lu gates are not present interrupt gates of the kernel code segment\n",
           Number, Cpu->BadGateFields);

        if (Cpu->Active)
        {
            ok(Cpu->StubGates == Cpu->PlainGates, "Processor %lu: %lu of %lu gates without an IST point at their stub\n",
               Number, Cpu->StubGates, Cpu->PlainGates);
            ok(Cpu->MissingHandlers == 0, "Processor %lu: %lu vectors have no handler behind their stub\n",
               Number, Cpu->MissingHandlers);
            ok(Cpu->IstGatesInStubTable == 0, "Processor %lu: %lu gates with an IST point into the stub table\n",
               Number, Cpu->IstGatesInStubTable);
            ok(Cpu->ExitPointerSet, "Processor %lu has no exit stub pointer\n", Number);
            ok(Cpu->Rsp0IsTransitionTop, "Processor %lu: TSS.Rsp0 is not the top of the transition stack\n", Number);
        }
        else
        {
            ok(Cpu->StubGates != Cpu->PlainGates, "Processor %lu: all %lu gates without an IST point at stubs although inactive\n",
               Number, Cpu->PlainGates);
            ok(!Cpu->Rsp0IsTransitionTop, "Processor %lu: TSS.Rsp0 is the transition stack although inactive\n", Number);
        }
    }

    ok(Count == (ULONG)Record->Calls, "Recorded %lu processors, the worker ran on %ld\n", Count, Record->Calls);
    ExFreePoolWithTag(Record, 'tvKK');
}

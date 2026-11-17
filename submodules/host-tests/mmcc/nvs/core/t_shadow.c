/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     A process address space with a shadow root keeps the user half of both roots identical
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "mmharness.h"

#define SHADOW_TEST_PAGES 6

static
ULONG
ShadowTopIndex(
    _In_ ULONG64 VirtualAddress)
{
    const MI_ARCH_DESCRIPTOR *Arch = MiArchDescribe();
    LONG Top = Arch->PagingLevels - 1;

    return (ULONG)((VirtualAddress >> Arch->Level[Top].Shift) & Arch->Level[Top].IndexMask);
}

static
MI_PTE
ShadowEntry(
    _In_ ULONG Frame,
    _In_ ULONG Index)
{
    PMI_PTE Table = MiArchMapFrame(Frame);
    MI_PTE Value = MiArchPteRead(&Table[Index]);

    MiArchUnmapFrame(Table);
    return Value;
}

static
ULONG
ShadowUsedEntries(
    _In_ ULONG Frame)
{
    const MI_ARCH_DESCRIPTOR *Arch = MiArchDescribe();
    ULONG Entries = (ULONG)Arch->Level[Arch->PagingLevels - 1].EntryCount;
    PMI_PTE Table = MiArchMapFrame(Frame);
    ULONG Index, Used = 0;

    for (Index = 0; Index < Entries; Index++)
    {
        if (MiArchPteRead(&Table[Index]) != 0)
            Used++;
    }
    MiArchUnmapFrame(Table);
    return Used;
}

void
TestShadowRoot(void)
{
    const MI_ARCH_DESCRIPTOR *Arch = MiArchDescribe();
    ULONG64 Span = 1ULL << Arch->Level[Arch->PagingLevels - 1].Shift;
    ULONG64 LastSlotBase = Arch->UserAddressEnd & ~(Span - 1);
    TEST_WORLD World;
    MI_ADDRESS_SPACE Plain, Space;
    PMI_SYSTEM System;
    ULONG64 Addresses[SHADOW_TEST_PAGES];
    ULONG Frames[SHADOW_TEST_PAGES];
    ULONG Tables[SHADOW_TEST_PAGES];
    PMI_PTE Slots[SHADOW_TEST_PAGES];
    LONG64 Available;
    ULONG i;

    WorldCreate(&World, 8192, 2, 100000);
    System = &World.System;
    Available = (LONG64)MiPfnAvailablePages(&System->Pfn);

    CHECK(!System->ShadowRoots);
    CHECK(System->SystemSpace.ShadowRootFrame == 0);
    CHECK(NT_SUCCESS(MiAddressSpaceCreate(System, &Plain)));
    CHECK(Plain.ShadowRootFrame == 0);
    CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available - 1);
    CHECK(MiPtCheck(&Plain) == 0);
    MiAddressSpaceDestroy(&Plain);
    CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available);

    System->ShadowRoots = TRUE;
    CHECK(NT_SUCCESS(MiAddressSpaceCreate(System, &Space)));
    CHECK(Space.ShadowRootFrame != 0 && Space.ShadowRootFrame != Space.RootFrame);
    CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available - 2);
    CHECK(ShadowUsedEntries(Space.ShadowRootFrame) == 0);
    CHECK(MiPtCheck(&Space) == 0);

    Addresses[0] = 0x10000;
    Addresses[1] = 0x10000 + PAGE_SIZE;
    Addresses[2] = (Span < LastSlotBase) ? Span + 0x20000 : 0x400000;
    Addresses[3] = (3 * Span < LastSlotBase) ? 3 * Span + 0x30000 : 0x800000;
    Addresses[4] = LastSlotBase + 0x40000;
    Addresses[5] = LastSlotBase + 0x40000 + PAGE_SIZE;

    for (i = 0; i < SHADOW_TEST_PAGES; i++)
    {
        ULONG Index = ShadowTopIndex(Addresses[i]);

        Slots[i] = MiPtEnsure(&Space, Addresses[i], &Tables[i]);
        CHECK(Slots[i] != NULL);
        if (Slots[i] == NULL)
        {
            Frames[i] = MI_FRAME_INVALID;
            continue;
        }

        Frames[i] = MiPfnAllocatePage(&System->Pfn, MI_ALLOCATE_ZEROED);
        CHECK(Frames[i] != MI_FRAME_INVALID);
        MiPfnInitializePage(&System->Pfn, Frames[i], MiPtSlotAddress(Slots[i], Tables[i], Addresses[i]), Tables[i],
                            MiSoftMake(MiSoftDemandZero, MI_PROT_READWRITE, 0), 0);
        MiPtWrite(&Space, Addresses[i], Slots[i], Tables[i],
                  MiArchPteMakeLeaf(Frames[i], MI_PROT_READWRITE, MI_LEAF_USER | MI_LEAF_DIRTY));

        CHECK(ShadowEntry(Space.RootFrame, Index) != 0);
        CHECK(ShadowEntry(Space.ShadowRootFrame, Index) == ShadowEntry(Space.RootFrame, Index));
        CHECK(MiPtCheck(&Space) == 0);
    }

    CHECK(ShadowUsedEntries(Space.ShadowRootFrame) >= 2);
    CHECK(ShadowUsedEntries(Space.ShadowRootFrame) <= SHADOW_TEST_PAGES);

    {
        ULONG Index = ShadowTopIndex(Addresses[0]);
        PMI_PTE Shadow = MiArchMapFrame(Space.ShadowRootFrame);
        MI_PTE Saved = MiArchPteRead(&Shadow[Index]);

        MiArchPteWrite(&Shadow[Index], 0);
        CHECK(MiPtCheck(&Space) == 1);
        CHECK(MiArchPteIsAccessed(Saved));
        MiArchPteWrite(&Shadow[Index], MiArchPteSetAccessed(Saved, FALSE));
        CHECK(MiPtCheck(&Space) == 0);
        MiArchPteWrite(&Shadow[Index], Saved);
        MiArchUnmapFrame(Shadow);
        CHECK(MiPtCheck(&Space) == 0);
    }

    for (i = 0; i < SHADOW_TEST_PAGES; i++)
    {
        if (Frames[i] == MI_FRAME_INVALID)
            continue;

        MiPtWrite(&Space, Addresses[i], Slots[i], Tables[i], 0);
        MiArchTlbInvalidate(Addresses[i], 1, TRUE);
        MiPfnShareDecrement(&System->Pfn, Frames[i], TRUE);
        CHECK(MiPtCheck(&Space) == 0);
    }

    MiPtFlushEmpty(&Space);
    CHECK(MiPtCheck(&Space) == 0);
    CHECK(Space.PageTablePages == 0);
    CHECK(ShadowUsedEntries(Space.ShadowRootFrame) == 0);
    for (i = 0; i < SHADOW_TEST_PAGES; i++)
        CHECK(ShadowEntry(Space.RootFrame, ShadowTopIndex(Addresses[i])) == 0);

    CHECK(WorldCheck(&World) == 0);
    MiAddressSpaceDestroy(&Space);
    CHECK(Space.ShadowRootFrame == 0);
    CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available);
    CHECK(WorldCheck(&World) == 0);

    {
        MI_ADDRESS_SPACE Parent, Child;
        ULONG64 Base = USER_BASE, Size = 4 * PAGE_SIZE;
        NTSTATUS Status;

        ProcessCreate(&World, &Parent);
        ProcessCreate(&World, &Child);
        CHECK(Parent.ShadowRootFrame != 0 && Child.ShadowRootFrame != 0);
        WorldAttach(&World, 0, &Parent);
        WorldAttach(&World, 1, &Child);
        CHECK(NT_SUCCESS(MiAllocateVirtualMemory(&Parent, &Base, &Size,
                                                 MI_MEM_RESERVE | MI_MEM_COMMIT, MI_PROT_READWRITE)));
        CHECK(NT_SUCCESS(UserWrite64(&World, 0, Base, 0x11223344)));
        Status = MiCloneAddressSpace(&Parent, &Child);
        CHECK(Status == STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            CHECK(UserRead64(&World, 1, Base, &Status) == 0x11223344 && NT_SUCCESS(Status));
            CHECK(NT_SUCCESS(UserWrite64(&World, 1, Base + PAGE_SIZE, 0xABCDEF)));
            CHECK(ShadowEntry(Child.RootFrame, ShadowTopIndex(Base)) != 0);
            CHECK(MiPtCheck(&Parent) == 0);
            CHECK(MiPtCheck(&Child) == 0);
        }
        WorldAttach(&World, 0, NULL);
        WorldAttach(&World, 1, NULL);
        ProcessDestroy(&World, &Child);
        ProcessDestroy(&World, &Parent);
        CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available);
    }

    {
        static ULONG Held[8192];
        MI_ADDRESS_SPACE Starved;
        ULONG Count = 0;

        while (MiPfnAvailablePages(&System->Pfn) > 1 && Count < 8192)
        {
            ULONG Frame = MiPfnAllocatePage(&System->Pfn, 0);

            if (Frame == MI_FRAME_INVALID)
                break;
            MiPfnInitializePage(&System->Pfn, Frame, 0, 0, 0, 0);
            Held[Count++] = Frame;
        }
        if (MiPfnAvailablePages(&System->Pfn) == 1)
        {
            CHECK(MiAddressSpaceCreate(System, &Starved) == STATUS_NO_MEMORY);
            CHECK(Starved.RootFrame == 0 && Starved.ShadowRootFrame == 0);
            CHECK(MiPfnAvailablePages(&System->Pfn) == 1);
        }
        while (Count != 0)
            MiPfnShareDecrement(&System->Pfn, Held[--Count], TRUE);
        CHECK((LONG64)MiPfnAvailablePages(&System->Pfn) == Available);
    }

    System->ShadowRoots = FALSE;
    WorldDestroy(&World);
}

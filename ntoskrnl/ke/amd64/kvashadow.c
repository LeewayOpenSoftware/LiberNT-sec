/*
 * PROJECT:     LiberNT Kernel
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel virtual address shadow: processor requirement, boot policy and reporting
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <ntoskrnl.h>
#include <x86x64/Cpuid.h>
#define NDEBUG
#include <debug.h>

#define KI_MSR_ARCH_CAPABILITIES 0x10A
#define KI_ARCH_CAPABILITIES_RDCL_NO 0x1

typedef enum _KI_KVA_SHADOW_POLICY
{
    KiKvaShadowPolicyOff,
    KiKvaShadowPolicyOn,
    KiKvaShadowPolicyAuto,
    KiKvaShadowPolicyTransition
} KI_KVA_SHADOW_POLICY;

typedef struct _KI_KVA_SHADOW_STATE
{
    KI_KVA_SHADOW_POLICY Policy;
    BOOLEAN PcidAllowed;
    BOOLEAN Required;
    BOOLEAN Pcid;
    BOOLEAN Invpcid;
    BOOLEAN Active;
} KI_KVA_SHADOW_STATE;

static KI_KVA_SHADOW_STATE KiKvaShadowState;

extern UCHAR KiKvaShadowVectorStubs[];
VOID KiKvaShadowSystemCall64(VOID);
VOID KiKvaShadowSystemCall32(VOID);
VOID KiKvaShadowExitIretq(VOID);

#define KI_KVA_STUB_SIZE 16

CODE_SEG("INIT")
static
BOOLEAN
KiIsKvaShadowRequired(
    _In_ PKPRCB Prcb,
    _In_ ULONG MaxLeaf)
{
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_REGS ExtFlags;

    if (Prcb->CpuVendor == CPU_AMD)
        return FALSE;

    if (MaxLeaf >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS)
    {
        __cpuidex(ExtFlags.AsInt32,
                  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS,
                  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO);
        if (ExtFlags.Edx.Bits.EnumeratesSupportForCapability &&
            (__readmsr(KI_MSR_ARCH_CAPABILITIES) & KI_ARCH_CAPABILITIES_RDCL_NO))
        {
            return FALSE;
        }
    }

    if (Prcb->CpuVendor == CPU_INTEL && Prcb->CpuType == 6)
    {
        /* KiSetProcessorType stores (ExtendedModel << 4 | Model) << 8 | Stepping for Intel family 6 */
        switch ((UCHAR)(Prcb->CpuStep >> 8))
        {
            case 0x1C:
            case 0x26:
            case 0x27:
            case 0x35:
            case 0x36:
                return FALSE;
        }
    }

    /* Every other processor, an unknown vendor included, is treated as affected */
    return TRUE;
}

CODE_SEG("INIT")
static
BOOLEAN
KiIsLoadOptionPresent(
    _In_ PCSTR Options,
    _In_ PCSTR Option)
{
    SIZE_T Length = strlen(Option);
    PCSTR Current;

    for (Current = Options; *Current != ANSI_NULL; Current++)
    {
        if ((Current == Options || Current[-1] == ' ' || Current[-1] == '/') &&
            _strnicmp(Current, Option, Length) == 0 &&
            (Current[Length] == ' ' || Current[Length] == '/' || Current[Length] == ANSI_NULL))
        {
            return TRUE;
        }
    }

    return FALSE;
}

CODE_SEG("INIT")
VOID
NTAPI
KiInitializeKvaShadow(
    _In_ PKPRCB Prcb,
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    CPUID_SIGNATURE_REGS Signature;
    CPUID_VERSION_INFO_REGS VersionInfo;
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_REGS ExtFlags;
    PCSTR Options = LoaderBlock->LoadOptions;

    __cpuid(Signature.AsInt32, CPUID_SIGNATURE);
    __cpuid(VersionInfo.AsInt32, CPUID_VERSION_INFO);

    KiKvaShadowState.Required = KiIsKvaShadowRequired(Prcb, Signature.MaxLeaf);
    KiKvaShadowState.Pcid = VersionInfo.Ecx.Bits.PCID != 0;
    if (Signature.MaxLeaf >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS)
    {
        __cpuidex(ExtFlags.AsInt32,
                  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS,
                  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO);
        KiKvaShadowState.Invpcid = ExtFlags.Ebx.Bits.INVPCID != 0;
    }

    KiKvaShadowState.Policy = KiKvaShadowPolicyOff;
    KiKvaShadowState.PcidAllowed = TRUE;
    if (Options != NULL)
    {
        if (KiIsLoadOptionPresent(Options, "KVASHADOW=ON"))
            KiKvaShadowState.Policy = KiKvaShadowPolicyOn;
        else if (KiIsLoadOptionPresent(Options, "KVASHADOW=AUTO"))
            KiKvaShadowState.Policy = KiKvaShadowPolicyAuto;
        else if (KiIsLoadOptionPresent(Options, "KVASHADOW=TRANSITION"))
            KiKvaShadowState.Policy = KiKvaShadowPolicyTransition;
        if (KiIsLoadOptionPresent(Options, "KVASHADOWPCID=OFF"))
            KiKvaShadowState.PcidAllowed = FALSE;
    }

    /* TODO: the shadow address space is not implemented, so no policy activates it */
    KiKvaShadowState.Active = FALSE;

    DPRINT1("KVA shadow: required %u, policy %u, PCID %u (allowed %u), INVPCID %u, active %u\n",
            KiKvaShadowState.Required,
            KiKvaShadowState.Policy,
            KiKvaShadowState.Pcid,
            KiKvaShadowState.PcidAllowed,
            KiKvaShadowState.Invpcid,
            KiKvaShadowState.Active);

    KiActivateKvaShadow(CONTAINING_RECORD(Prcb, KIPCR, Prcb));
}

VOID
NTAPI
KiActivateKvaShadow(
    _Inout_ PKIPCR Pcr)
{
    PKIDTENTRY64 Idt = Pcr->IdtBase;
    PKIPCR BootPcr;
    ULONG64 Stub;
    ULONG Index;

    /* TODO: only the transition mode exists, where both directory table bases are the same root */
    if (KiKvaShadowState.Policy != KiKvaShadowPolicyTransition)
        return;

    if (Pcr->Prcb.Number == 0)
    {
        for (Index = 0; Index < 256; Index++)
        {
            Pcr->KvaShadowHandlers[Index] = (PVOID)((ULONG64)Idt[Index].OffsetHigh << 32 |
                                                    (ULONG64)Idt[Index].OffsetMiddle << 16 |
                                                    (ULONG64)Idt[Index].OffsetLow);
        }
    }
    else
    {
        BootPcr = CONTAINING_RECORD(KiProcessorBlock[0], KIPCR, Prcb);
        RtlCopyMemory(Pcr->KvaShadowHandlers, BootPcr->KvaShadowHandlers, sizeof(Pcr->KvaShadowHandlers));
    }

    for (Index = 0; Index < 256; Index++)
    {
        if (Idt[Index].IstIndex != 0)
        {
            ASSERT(Index == 2 || Index == 8 || Index == 18);
            continue;
        }

        Stub = (ULONG64)&KiKvaShadowVectorStubs[Index * KI_KVA_STUB_SIZE];
        Idt[Index].OffsetLow = Stub & 0xffff;
        Idt[Index].Selector = KGDT64_R0_CODE;
        Idt[Index].Reserved0 = 0;
        Idt[Index].Type = 0x0e;
        Idt[Index].Present = 1;
        Idt[Index].OffsetMiddle = (Stub >> 16) & 0xffff;
        Idt[Index].OffsetHigh = (ULONG)(Stub >> 32);
        Idt[Index].Reserved1 = 0;
    }

    Pcr->KvaShadowExitIretq = KiKvaShadowExitIretq;
    Pcr->TssBase->Rsp0 = (ULONG64)&Pcr->KvaShadowTransitionStack[sizeof(Pcr->KvaShadowTransitionStack)];
    __writemsr(MSR_LSTAR, (ULONG64)KiKvaShadowSystemCall64);
    __writemsr(MSR_CSTAR, (ULONG64)KiKvaShadowSystemCall32);
    Pcr->KvaShadow.ShadowFlags |= KVA_SHADOW_ACTIVE;
}

NTSTATUS
NTAPI
KiQueryKernelVaShadowInformation(
    _Out_ PULONG Flags)
{
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION Information;

    Information.KvaShadowFlags = 0;
    Information.KvaShadowRequired = KiKvaShadowState.Required;
    Information.KvaShadowRequiredAvailable = 1;
    if (KiKvaShadowState.Active)
    {
        Information.KvaShadowEnabled = 1;
        Information.KvaShadowPcid = KiKvaShadowState.Pcid && KiKvaShadowState.PcidAllowed;
        Information.KvaShadowInvpcid = Information.KvaShadowPcid && KiKvaShadowState.Invpcid;
    }

    *Flags = Information.KvaShadowFlags;
    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
KiShadowAddressSpacesRequested(VOID)
{
    return KiKvaShadowState.Policy == KiKvaShadowPolicyOn ||
           KiKvaShadowState.Policy == KiKvaShadowPolicyTransition ||
           (KiKvaShadowState.Policy == KiKvaShadowPolicyAuto && KiKvaShadowState.Required);
}

VOID
NTAPI
KiSetProcessShadowDirectoryTableBase(
    _Inout_ PKPROCESS Process,
    _In_ ULONG64 DirectoryTableBase)
{
    Process->UserDirectoryTableBase = DirectoryTableBase;
}

/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     CR4.SMEP matches CPU capability and the NOSMEP boot option on every processor
 * COPYRIGHT:   Copyright 2026 LeewayOpenSoftware
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#define CR4_SMEP_MASK  0x00100000ULL
#define CPUID7_EBX_SMEP (1u << 7)

static
BOOLEAN
KmtCpuSupportsSmep(VOID)
{
    int Regs[4];

    __cpuid(Regs, 0);
    if ((unsigned int)Regs[0] < 7)
        return FALSE;

    __cpuidex(Regs, 7, 0);
    return (Regs[1] & CPUID7_EBX_SMEP) != 0;
}

static
BOOLEAN
KmtBootOptionNoSmep(
    _Out_ PBOOLEAN Found)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"SystemStartOptions");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG Length = 0;
    NTSTATUS Status;

    *Found = FALSE;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation,
                             NULL, 0, &Length);
    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW)
    {
        ZwClose(KeyHandle);
        return FALSE;
    }

    Info = ExAllocatePoolWithTag(PagedPool, Length + sizeof(WCHAR), 'SktM');
    if (Info == NULL)
    {
        ZwClose(KeyHandle);
        return FALSE;
    }

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation,
                             Info, Length, &Length);
    ZwClose(KeyHandle);

    if (NT_SUCCESS(Status) && Info->Type == REG_SZ && Info->DataLength >= sizeof(WCHAR))
    {
        PCWSTR Options = (PCWSTR)Info->Data;
        SIZE_T Count = Info->DataLength / sizeof(WCHAR);
        SIZE_T OptionLength = wcslen(L"NOSMEP");
        SIZE_T Index;

        for (Index = 0; Index + OptionLength <= Count; Index++)
        {
            WCHAR After;

            if (Index != 0 && Options[Index - 1] != L' ' && Options[Index - 1] != L'/')
                continue;
            if (_wcsnicmp(&Options[Index], L"NOSMEP", OptionLength) != 0)
                continue;

            After = (Index + OptionLength < Count) ? Options[Index + OptionLength] : UNICODE_NULL;
            if (After == L' ' || After == L'/' || After == UNICODE_NULL)
            {
                *Found = TRUE;
                break;
            }
        }

        ExFreePoolWithTag(Info, 'SktM');
        return TRUE;
    }

    ExFreePoolWithTag(Info, 'SktM');
    return FALSE;
}

START_TEST(KeSmep)
{
    KAFFINITY ActiveProcessors;
    ULONG Index;
    BOOLEAN HaveBootOption;
    BOOLEAN NoSmepRequested = FALSE;
    LONG FirstState = -1;

    ActiveProcessors = KeQueryActiveProcessors();
    HaveBootOption = KmtBootOptionNoSmep(&NoSmepRequested);

    trace("Active processor mask 0x%Ix; NOSMEP boot option %s\n",
          (ULONG_PTR)ActiveProcessors,
          HaveBootOption ? (NoSmepRequested ? "present" : "absent")
                         : "unreadable");

    for (Index = 0; Index < sizeof(KAFFINITY) * 8; Index++)
    {
        KAFFINITY Mask = (KAFFINITY)1 << Index;
        KAFFINITY OldAffinity;
        BOOLEAN Supported;
        BOOLEAN Enabled;

        if ((ActiveProcessors & Mask) == 0)
            continue;

        OldAffinity = KeSetSystemAffinityThreadEx(Mask);

        Supported = KmtCpuSupportsSmep();
        Enabled = (__readcr4() & CR4_SMEP_MASK) != 0;

        KeRevertToUserAffinityThreadEx(OldAffinity);

        ok(!(Enabled && !Supported),
           "CPU %lu: CR4.SMEP set but CPUID does not report SMEP\n", Index);

        if (Supported && HaveBootOption && !NoSmepRequested)
        {
            ok(Enabled, "CPU %lu: SMEP supported, NOSMEP absent, but CR4.SMEP is clear\n", Index);
        }

        if (HaveBootOption && NoSmepRequested)
        {
            ok(!Enabled, "CPU %lu: NOSMEP requested but CR4.SMEP is set\n", Index);
        }

        if (FirstState < 0)
            FirstState = Enabled ? 1 : 0;
        else if ((LONG)(Enabled ? 1 : 0) != FirstState)
            trace("CPU %lu: CR4.SMEP=%d differs from CPU0 (%ld) - expected only on heterogeneous CPUs\n",
                  Index, Enabled, FirstState);

        trace("CPU %lu: SMEP supported=%d, CR4.SMEP=%d\n", Index, Supported, Enabled);
    }
}

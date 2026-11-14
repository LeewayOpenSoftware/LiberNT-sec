/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TokenAuditPolicy changes only the categories the caller names
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>
#include <ndk/setypes.h>
#include <ndk/sefuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>

/* Categories are the POLICY_AUDIT_EVENT_TYPE values of ntsecapi.h: 0 System .. 8 AccountLogon */
#define CATEGORY_COUNT 9

/* The set-only class takes the kernel's TOKEN_AUDIT_POLICY_INFORMATION layout */
typedef struct _TEST_AUDIT_POLICY_INFORMATION
{
    ULONG PolicyCount;
    struct
    {
        ULONG Category;
        UCHAR Value;
    } Policies[CATEGORY_COUNT];
} TEST_AUDIT_POLICY_INFORMATION;

static
UCHAR
ReadCategory(
    _In_ const SEP_AUDIT_POLICY *Policy,
    _In_ ULONG Category)
{
    switch (Category)
    {
        case 0: return Policy->PolicyElements.System;
        case 1: return Policy->PolicyElements.Logon;
        case 2: return Policy->PolicyElements.ObjectAccess;
        case 3: return Policy->PolicyElements.PrivilegeUse;
        case 4: return Policy->PolicyElements.DetailedTracking;
        case 5: return Policy->PolicyElements.PolicyChange;
        case 6: return Policy->PolicyElements.AccountManagement;
        case 7: return Policy->PolicyElements.DirectoryServiceAccess;
        case 8: return Policy->PolicyElements.AccountLogon;
    }
    return 0xFF;
}

/* Sets Count categories starting at First to the values in Expected */
static
NTSTATUS
SetCategories(
    _In_ HANDLE Token,
    _In_ const UCHAR *Expected,
    _In_ ULONG First,
    _In_ ULONG Count)
{
    TEST_AUDIT_POLICY_INFORMATION Info;
    ULONG i;

    Info.PolicyCount = Count;
    for (i = 0; i < Count; i++)
    {
        Info.Policies[i].Category = First + i;
        Info.Policies[i].Value = Expected[First + i];
    }
    return ZwSetInformationToken(Token,
                                 TokenAuditPolicy,
                                 &Info,
                                 FIELD_OFFSET(TEST_AUDIT_POLICY_INFORMATION, Policies[Count]));
}

static
VOID
CheckCategories(
    _In_ PTOKEN Token,
    _In_ const UCHAR *Expected,
    _In_ PCSTR Step)
{
    ULONG i;

    for (i = 0; i < CATEGORY_COUNT; i++)
    {
        UCHAR Value = ReadCategory(&Token->AuditPolicy, i);
        ok(Value == Expected[i], "%s: category %lu is %u, expected %u\n", Step, i, Value, Expected[i]);
    }
}

START_TEST(SeTokenAuditPolicy)
{
    PACCESS_TOKEN AccessToken;
    PTOKEN Token;
    HANDLE Handle;
    SEP_AUDIT_POLICY Original;
    UCHAR Expected[CATEGORY_COUNT];
    NTSTATUS Status;
    ULONG i;

    AccessToken = PsReferencePrimaryToken(PsGetCurrentProcess());
    Token = (PTOKEN)AccessToken;
    Original = Token->AuditPolicy;

    Status = ObOpenObjectByPointer(AccessToken,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   TOKEN_ADJUST_DEFAULT,
                                   *SeTokenObjectType,
                                   KernelMode,
                                   &Handle);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        PsDereferencePrimaryToken(AccessToken);
        return;
    }

    /* Every category gets a known value */
    for (i = 0; i < CATEGORY_COUNT; i++)
        Expected[i] = (UCHAR)(i + 1);
    Status = SetCategories(Handle, Expected, 0, CATEGORY_COUNT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckCategories(Token, Expected, "all categories");

    /* One category named: the others keep what they had */
    Expected[1] = 0xA;
    Status = SetCategories(Handle, Expected, 1, 1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckCategories(Token, Expected, "one category");

    /* Two categories named, the first and the last */
    Expected[0] = 0xB;
    Expected[8] = 0xC;
    {
        TEST_AUDIT_POLICY_INFORMATION Info;

        Info.PolicyCount = 2;
        Info.Policies[0].Category = 0;
        Info.Policies[0].Value = Expected[0];
        Info.Policies[1].Category = 8;
        Info.Policies[1].Value = Expected[8];
        Status = ZwSetInformationToken(Handle,
                                       TokenAuditPolicy,
                                       &Info,
                                       FIELD_OFFSET(TEST_AUDIT_POLICY_INFORMATION, Policies[2]));
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckCategories(Token, Expected, "two categories");

    /* An empty list changes nothing */
    Status = SetCategories(Handle, Expected, 0, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckCategories(Token, Expected, "empty list");

    /* Put the token's own policy back */
    for (i = 0; i < CATEGORY_COUNT; i++)
        Expected[i] = ReadCategory(&Original, i);
    Status = SetCategories(Handle, Expected, 0, CATEGORY_COUNT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckCategories(Token, Expected, "restored");

    ObCloseHandle(Handle, KernelMode);
    PsDereferencePrimaryToken(AccessToken);
}

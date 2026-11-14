/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The module name given to NtUserSetWindowsHookEx
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

static
LRESULT
CALLBACK
HookProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static
VOID
TestBadName(USHORT Length, USHORT MaximumLength, PWSTR Buffer)
{
    UNICODE_STRING Name;
    HHOOK Hook;

    Name.Length = Length;
    Name.MaximumLength = MaximumLength;
    Name.Buffer = Buffer;

    SetLastError(0xdeadbeef);
    Hook = NtUserSetWindowsHookEx(GetModuleHandleW(NULL),
                                  &Name,
                                  GetCurrentThreadId(),
                                  WH_GETMESSAGE,
                                  HookProc,
                                  FALSE);
    ok(Hook == NULL, "Length %u MaximumLength %u: the hook was installed\n", Length, MaximumLength);
    if (Hook)
    {
        /* Do not let it be called: its name is not usable */
        NtUserUnhookWindowsHookEx(Hook);
        return;
    }
    ok(GetLastError() == ERROR_INVALID_PARAMETER,
       "Length %u MaximumLength %u: GetLastError() = %lu\n", Length, MaximumLength, GetLastError());
}

START_TEST(NtUserSetWindowsHookEx)
{
    static WCHAR Short[8] = L"a.dll";
    static WCHAR Long[600];
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Long) - 1; i++)
        Long[i] = L'x';

    /* More characters than the buffer holds */
    TestBadName(0x400, sizeof(Short), Short);
    TestBadName(sizeof(Short) + sizeof(WCHAR), sizeof(Short), Short);

    /* Half a character */
    TestBadName(5, sizeof(Short), Short);

    /* A name that the hook callback cannot carry (512 characters with the terminator) */
    TestBadName(512 * sizeof(WCHAR), sizeof(Long), Long);
    TestBadName(599 * sizeof(WCHAR), sizeof(Long), Long);
}

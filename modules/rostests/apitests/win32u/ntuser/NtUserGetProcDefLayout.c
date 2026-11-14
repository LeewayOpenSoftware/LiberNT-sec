/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the default layout query (NtUserCallOneParam)
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

START_TEST(NtUserGetProcDefLayout)
{
    DWORD dwLayout = 0xdeadbeef;

    /* A buffer of the caller is written */
    TEST(NtUserCallOneParam((DWORD_PTR)&dwLayout, ONEPARAM_ROUTINE_GETPROCDEFLAYOUT) == TRUE);
    TEST(dwLayout != 0xdeadbeef);

    /* A kernel address is refused */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserCallOneParam((DWORD_PTR)(LONG_PTR)-4096, ONEPARAM_ROUTINE_GETPROCDEFLAYOUT) == FALSE);
    TEST(GetLastError() == ERROR_NOACCESS);
}

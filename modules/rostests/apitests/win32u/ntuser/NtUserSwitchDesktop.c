/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for NtUserSwitchDesktop
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

START_TEST(NtUserSwitchDesktop)
{
    HDESK hDesk;

    /* Without DESKTOP_SWITCHDESKTOP: refused */
    hDesk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!hDesk)
    {
        skip("OpenInputDesktop failed with %lu\n", GetLastError());
        return;
    }
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserSwitchDesktop(hDesk) == FALSE);
    TEST(GetLastError() == ERROR_ACCESS_DENIED);
    CloseDesktop(hDesk);

    /* With it: switching to the input desktop succeeds */
    hDesk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (!hDesk)
    {
        skip("OpenInputDesktop with DESKTOP_SWITCHDESKTOP failed with %lu\n", GetLastError());
        return;
    }
    TEST(NtUserSwitchDesktop(hDesk) != FALSE);
    CloseDesktop(hDesk);
}

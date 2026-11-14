/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for registering the logon process (NtUserCallTwoParam)
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

/* Only the cases that cannot disturb the real logon process: this process is
 * never the logon process of its session, and it never names another one */
START_TEST(NtUserRegisterLogonProcess)
{
    DWORD_PTR Self = (DWORD_PTR)GetCurrentProcessId();

    /* The session has its logon process already: a second registrant is refused */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserCallTwoParam(Self, TRUE, TWOPARAM_ROUTINE_REGISTERLOGONPROCESS) == FALSE);
    TEST(GetLastError() == ERROR_ACCESS_DENIED);

    /* A process that is not the logon process cannot deregister */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserCallTwoParam(Self, FALSE, TWOPARAM_ROUTINE_REGISTERLOGONPROCESS) == FALSE);
    TEST(GetLastError() == ERROR_ACCESS_DENIED);

    /* Naming another process is refused before anything is looked up
     * (a process id that does not exist, so nothing real is touched) */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserCallTwoParam(Self + 4, TRUE, TWOPARAM_ROUTINE_REGISTERLOGONPROCESS) == FALSE);
    TEST(GetLastError() == ERROR_ACCESS_DENIED);
}

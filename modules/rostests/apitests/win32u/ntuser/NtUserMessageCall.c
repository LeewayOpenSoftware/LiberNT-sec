/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Message numbers that the send and post services accept
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"
#include <undocuser.h>

/* The first message number that win32k keeps for itself. Sent to a window with
   wParam SW_HIDE it would hide the window. */
#define INTERNAL_MESSAGE 0x80000000

START_TEST(NtUserMessageCall)
{
    HINSTANCE hinst = GetModuleHandle(NULL);
    ULONG_PTR Result;
    LRESULT Ret;
    HWND hWnd;
    MSG Msg;

    hWnd = CreateWindowA("BUTTON", "Test", BS_PUSHBUTTON | WS_VISIBLE,
                         0, 0, 50, 30, NULL, NULL, hinst, 0);
    ok(hWnd != NULL, "CreateWindowA failed: %lu\n", GetLastError());
    if (!hWnd)
        return;
    ok(IsWindowVisible(hWnd), "The window is not visible\n");

    /* An ordinary message goes through */
    Result = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    NtUserMessageCall(hWnd, WM_NULL, 0, 0, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(Result == 0, "Result = %Iu\n", Result);
    ok(GetLastError() == 0xdeadbeef, "GetLastError() = %lu\n", GetLastError());

    /* Sending */
    Result = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = NtUserMessageCall(hWnd, INTERNAL_MESSAGE, SW_HIDE, 0, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    ok(Result == 0xdeadbeef, "Result = %Iu\n", Result);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());
    ok(IsWindowVisible(hWnd), "The window was hidden\n");

    SetLastError(0xdeadbeef);
    Ret = NtUserMessageCall(hWnd, INTERNAL_MESSAGE, SW_HIDE, 0, 0, FNID_SENDNOTIFYMESSAGE, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());
    ok(IsWindowVisible(hWnd), "The window was hidden\n");

    SetLastError(0xdeadbeef);
    Ret = NtUserMessageCall(hWnd, WM_MAXIMUM + 1, 0, 0, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    /* Posting */
    SetLastError(0xdeadbeef);
    ok(NtUserPostMessage(hWnd, INTERNAL_MESSAGE, SW_HIDE, 0) == FALSE, "NtUserPostMessage succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ok(NtUserPostThreadMessage(GetCurrentThreadId(), INTERNAL_MESSAGE, SW_HIDE, 0) == FALSE,
       "NtUserPostThreadMessage succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    while (PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE))
    {
        ok(!(Msg.message & ~WM_MAXIMUM), "Message 0x%x in the queue\n", Msg.message);
        DispatchMessageA(&Msg);
    }
    ok(IsWindowVisible(hWnd), "The window was hidden\n");

    DestroyWindow(hWnd);
}

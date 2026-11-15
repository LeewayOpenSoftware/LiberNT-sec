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

/* The window procedures that run in the kernel, called the way user32 calls them */
static
VOID
TestKernelProcedures(HWND hWnd)
{
    /* An address that user mode can never own, on 32 and on 64 bits */
    const LPARAM KernelAddress = (LPARAM)~(ULONG_PTR)0xFFFF;
    static WCHAR NameW[] = L"Wide";
    static CHAR NameA[] = "Ansi";
    BROADCASTPARM Parm;
    WCHAR TextW[16];
    CHAR TextA[16];
    LRESULT Ret;
    RECT Rect;

    /* Text in and out, both character sets */
    Ret = NtUserMessageCall(hWnd, WM_SETTEXT, 0, (LPARAM)NameW, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == TRUE, "Ret = %Id\n", Ret);
    FillMemory(TextW, sizeof(TextW), 0x55);
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, RTL_NUMBER_OF(TextW), (LPARAM)TextW, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 4, "Ret = %Id\n", Ret);
    ok(!memcmp(TextW, L"Wide", 5 * sizeof(WCHAR)), "The text is not 'Wide'\n");
    ok(TextW[5] == 0x5555, "TextW[5] = 0x%x, written past the terminator\n", TextW[5]);

    FillMemory(TextW, sizeof(TextW), 0x55);
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, 3, (LPARAM)TextW, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 2, "Ret = %Id\n", Ret);
    ok(!memcmp(TextW, L"Wi", 3 * sizeof(WCHAR)), "The text is not 'Wi'\n");
    ok(TextW[3] == 0x5555, "TextW[3] = 0x%x, written past the count\n", TextW[3]);

    Ret = NtUserMessageCall(hWnd, WM_SETTEXT, 0, (LPARAM)NameA, 0, FNID_DEFWINDOWPROC, TRUE);
    ok(Ret == TRUE, "Ret = %Id\n", Ret);
    FillMemory(TextA, sizeof(TextA), 0x55);
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, sizeof(TextA), (LPARAM)TextA, 0, FNID_DEFWINDOWPROC, TRUE);
    ok(Ret == 4, "Ret = %Id\n", Ret);
    ok(!memcmp(TextA, "Ansi", 5), "The text is not 'Ansi'\n");
    ok(TextA[5] == 0x55, "TextA[5] = 0x%x, written past the terminator\n", TextA[5]);

    /* A window rectangle in and out */
    SetRect(&Rect, 10, 10, 310, 210);
    NtUserMessageCall(hWnd, WM_NCCALCSIZE, FALSE, (LPARAM)&Rect, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Rect.left >= 10 && Rect.top >= 10 && Rect.right <= 310 && Rect.bottom <= 210,
       "Rect = %ld,%ld,%ld,%ld\n", Rect.left, Rect.top, Rect.right, Rect.bottom);

    /* The same messages with an address in kernel space. An unfixed kernel
       writes to that address. */
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, 16, KernelAddress, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, 16, KernelAddress, 0, FNID_DEFWINDOWPROC, TRUE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_SETTEXT, 0, KernelAddress, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_NCCALCSIZE, FALSE, KernelAddress, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_WINDOWPOSCHANGING, 0, KernelAddress, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_WINDOWPOSCHANGED, 0, KernelAddress, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);

    /* The text is what it was */
    Ret = NtUserMessageCall(hWnd, WM_GETTEXT, RTL_NUMBER_OF(TextW), (LPARAM)TextW, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 4, "Ret = %Id\n", Ret);
    ok(!memcmp(TextW, L"Ansi", 5 * sizeof(WCHAR)), "The text is not 'Ansi'\n");

    /* The procedures of the desktop, menu and message-only classes do not run
       for a window of another class */
    Ret = NtUserMessageCall(hWnd, WM_NCCREATE, 0, 0, 0, FNID_DESKTOP, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_NCCREATE, 0, 0, 0, FNID_MENU, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_NCCREATE, 0, 0, 0, FNID_MESSAGEWND, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    Ret = NtUserMessageCall(hWnd, WM_WINDOWPOSCHANGING, 0, KernelAddress, 0, FNID_DESKTOP, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    ok(IsWindow(hWnd), "The window is gone\n");

    /* A broadcast whose lParam is an address in kernel space. The message is
       harmless; an unfixed kernel reads a string at that address. */
    ZeroMemory(&Parm, sizeof(Parm));
    Parm.recipients = BSM_ALLCOMPONENTS;
    NtUserMessageCall(NULL, WM_NULL, 0, KernelAddress, (ULONG_PTR)&Parm, FNID_BROADCASTSYSTEMMESSAGE, FALSE);
    ok(IsWindow(hWnd), "The window is gone\n");

    /* The default procedure does not run for a window of another process */
    SetLastError(0xdeadbeef);
    Ret = NtUserMessageCall(GetDesktopWindow(), WM_GETTEXTLENGTH, 0, 0, 0, FNID_DEFWINDOWPROC, FALSE);
    ok(Ret == 0, "Ret = %Id\n", Ret);
    ok(GetLastError() == ERROR_ACCESS_DENIED, "GetLastError() = %lu\n", GetLastError());
}

START_TEST(NtUserMessageCall)
{
    HINSTANCE hinst = GetModuleHandle(NULL);
    static BYTE Data[16];
    COPYDATASTRUCT Cds;
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

    /* A data length that makes the size of the whole message wrap. An unfixed
       kernel writes past a pool block here. */
    Cds.dwData = 0;
    Cds.cbData = 0xFFFFFFF0;
    Cds.lpData = Data;
    Result = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    NtUserMessageCall(hWnd, WM_COPYDATA, 0, (LPARAM)&Cds, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());
    ok((LRESULT)Result == -1, "Result = %Id, the message was delivered\n", (LRESULT)Result);

    Cds.cbData = 0xFFFFFFF8;
    Result = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    NtUserMessageCall(hWnd, WM_COPYDATA, 0, (LPARAM)&Cds, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());
    ok((LRESULT)Result == -1, "Result = %Id, the message was delivered\n", (LRESULT)Result);

    /* An ordinary one still goes through */
    Cds.cbData = sizeof(Data);
    Result = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    NtUserMessageCall(hWnd, WM_COPYDATA, 0, (LPARAM)&Cds, (ULONG_PTR)&Result, FNID_SENDMESSAGE, FALSE);
    ok(Result == 0, "Result = %Iu\n", Result);
    ok(GetLastError() == 0xdeadbeef, "GetLastError() = %lu\n", GetLastError());

    /* Posting */
    SetLastError(0xdeadbeef);
    ok(NtUserPostMessage(hWnd, INTERNAL_MESSAGE, SW_HIDE, 0) == FALSE, "NtUserPostMessage succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ok(NtUserPostThreadMessage(GetCurrentThreadId(), INTERNAL_MESSAGE, SW_HIDE, 0) == FALSE,
       "NtUserPostThreadMessage succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    TestKernelProcedures(hWnd);

    while (PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE))
    {
        ok(!(Msg.message & ~WM_MAXIMUM), "Message 0x%x in the queue\n", Msg.message);
        DispatchMessageA(&Msg);
    }
    ok(IsWindowVisible(hWnd), "The window was hidden\n");

    DestroyWindow(hWnd);
}

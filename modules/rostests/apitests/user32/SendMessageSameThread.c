/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Messages with a pointer in lParam, sent to a window of the calling thread
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

#include <undocuser.h>

#define REPLY_MARKER 0x1234

static UINT s_Expected;
static ULONG s_Calls;
static LPARAM s_SeenLParam;
static BOOL s_PosSeen;

static
LRESULT
CALLBACK
HookProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static
LRESULT
CALLBACK
WndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (s_Expected && Msg == s_Expected)
    {
        s_Calls++;
        s_SeenLParam = lParam;
        if (Msg == WM_GETMINMAXINFO)
        {
            MINMAXINFO *Info = (MINMAXINFO *)lParam;

            ok(Info->ptMinTrackSize.x == 11, "ptMinTrackSize.x = %ld\n", Info->ptMinTrackSize.x);
            Info->ptMaxSize.x = 4321;
            Info->ptMaxSize.y = 8765;
        }
        else if (Msg == WM_NCCALCSIZE && wParam)
        {
            NCCALCSIZE_PARAMS *Params = (NCCALCSIZE_PARAMS *)lParam;

            ok(Params->rgrc[0].right == 100, "right = %ld\n", Params->rgrc[0].right);
            s_PosSeen = Params->lppos != NULL && Params->lppos->cx == 77;
            Params->rgrc[0].left = 5;
            if (Params->lppos)
                Params->lppos->cy = 66;
        }
        return REPLY_MARKER;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

START_TEST(SendMessageSameThread)
{
    /* An address that user mode can never own, on 32 and on 64 bits */
    const LPARAM KernelAddress = (LPARAM)~(ULONG_PTR)0xFFFF;
    static const WCHAR ClassName[] = L"SendMessageSameThreadTest";
    static WCHAR Text[] = L"same thread text";
    WNDCLASSW Class = { 0 };
    MINMAXINFO Info;
    NCCALCSIZE_PARAMS Params;
    WINDOWPOS Pos;
    CREATESTRUCTW Cs;
    HHOOK Hook;
    HWND hWnd;
    LRESULT Ret;

    Class.lpfnWndProc = WndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = ClassName;
    if (!RegisterClassW(&Class))
    {
        skip("RegisterClassW failed: %lu\n", GetLastError());
        return;
    }
    hWnd = CreateWindowExW(0, ClassName, L"", WS_OVERLAPPED, 0, 0, 100, 100,
                           NULL, NULL, Class.hInstance, NULL);
    if (!hWnd)
    {
        skip("CreateWindowExW failed: %lu\n", GetLastError());
        UnregisterClassW(ClassName, Class.hInstance);
        return;
    }

    /* With a call-window-procedure hook on the thread, user32 does not call the
       window procedure itself any more: every send goes through the kernel. */
    Hook = SetWindowsHookExW(WH_CALLWNDPROC, HookProc, NULL, GetCurrentThreadId());
    ok(Hook != NULL, "SetWindowsHookExW failed: %lu\n", GetLastError());
    if (!Hook)
        goto Done;

    /* A fixed size structure goes to the window procedure and its reply comes back */
    ZeroMemory(&Info, sizeof(Info));
    Info.ptMinTrackSize.x = 11;
    s_Expected = WM_GETMINMAXINFO;
    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_GETMINMAXINFO, 0, (LPARAM)&Info);
    ok(Ret == REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 1, "s_Calls = %lu\n", s_Calls);
    ok(Info.ptMaxSize.x == 4321 && Info.ptMaxSize.y == 8765,
       "ptMaxSize = %ld,%ld\n", Info.ptMaxSize.x, Info.ptMaxSize.y);

    /* The same message with an address in kernel space is not delivered */
    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_GETMINMAXINFO, 0, KernelAddress);
    ok(Ret != REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);

    /* A structure with a second pointer inside */
    ZeroMemory(&Params, sizeof(Params));
    ZeroMemory(&Pos, sizeof(Pos));
    Params.rgrc[0].right = 100;
    Params.lppos = &Pos;
    Pos.cx = 77;
    s_Expected = WM_NCCALCSIZE;
    s_Calls = 0;
    s_PosSeen = FALSE;
    Ret = SendMessageW(hWnd, WM_NCCALCSIZE, TRUE, (LPARAM)&Params);
    ok(Ret == REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 1, "s_Calls = %lu\n", s_Calls);
    ok(s_PosSeen, "The window procedure did not get the window position\n");
    ok(Params.rgrc[0].left == 5, "left = %ld\n", Params.rgrc[0].left);
    ok(Params.lppos == &Pos, "lppos = %p, expected %p\n", Params.lppos, &Pos);
    ok(Pos.cy == 66, "cy = %d\n", Pos.cy);

    /* The second pointer in kernel space */
    Params.lppos = (PWINDOWPOS)KernelAddress;
    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_NCCALCSIZE, TRUE, (LPARAM)&Params);
    ok(Ret != REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);
    ok(Params.lppos == (PWINDOWPOS)KernelAddress, "lppos = %p\n", Params.lppos);

    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_NCCALCSIZE, TRUE, KernelAddress);
    ok(Ret != REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);

    /* A string stays the caller's pointer */
    s_Expected = WM_SETTEXT;
    s_Calls = 0;
    s_SeenLParam = 0;
    Ret = SendMessageW(hWnd, WM_SETTEXT, 0, (LPARAM)Text);
    ok(Ret == REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 1, "s_Calls = %lu\n", s_Calls);
    ok(s_SeenLParam == (LPARAM)Text, "lParam = %p, expected %p\n", (PVOID)s_SeenLParam, Text);

    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_SETTEXT, 0, KernelAddress);
    ok(Ret != REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);

    /* Only window creation produces this message; its kernel format cannot come from an application */
    ZeroMemory(&Cs, sizeof(Cs));
    s_Expected = WM_CREATE;
    s_Calls = 0;
    Ret = SendMessageW(hWnd, WM_CREATE, 0, (LPARAM)&Cs);
    ok(Ret != REPLY_MARKER, "Ret = %Id\n", Ret);
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);

    /* A pointer message cannot be sent without waiting */
    s_Expected = WM_KLUDGEMINRECT;
    s_Calls = 0;
    SetLastError(0xdeadbeef);
    Ret = SendNotifyMessageW(hWnd, WM_KLUDGEMINRECT, 0, KernelAddress);
    ok(Ret == FALSE, "Ret = %Id\n", Ret);
    ok(GetLastError() == ERROR_MESSAGE_SYNC_ONLY, "GetLastError() = %lu\n", GetLastError());
    ok(s_Calls == 0, "s_Calls = %lu\n", s_Calls);

    s_Expected = 0;
    UnhookWindowsHookEx(Hook);

Done:
    DestroyWindow(hWnd);
    UnregisterClassW(ClassName, Class.hInstance);
}

/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for NtUserSetClassLong
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

START_TEST(NtUserSetClassLong)
{
    WNDCLASSW wc = { 0 };
    HWND hWnd;

    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"NtUserSetClassLongTest";
    wc.cbWndExtra = 8;
    if (!RegisterClassW(&wc))
    {
        skip("RegisterClassW failed with %lu\n", GetLastError());
        return;
    }
    hWnd = CreateWindowW(wc.lpszClassName, L"Test", WS_POPUP, 0, 0, 10, 10, NULL, NULL, wc.hInstance, NULL);
    if (!hWnd)
    {
        skip("CreateWindowW failed with %lu\n", GetLastError());
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return;
    }

    /* A negative extra window size is refused and the class keeps its size */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserSetClassLong(hWnd, GCL_CBWNDEXTRA, (ULONG)-1, FALSE) == 0);
    TEST(GetLastError() == ERROR_INVALID_PARAMETER);
    TEST(GetClassLongW(hWnd, GCL_CBWNDEXTRA) == 8);

    /* A positive one is accepted */
    TEST(NtUserSetClassLong(hWnd, GCL_CBWNDEXTRA, 16, FALSE) == 8);
    TEST(GetClassLongW(hWnd, GCL_CBWNDEXTRA) == 16);

    DestroyWindow(hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}

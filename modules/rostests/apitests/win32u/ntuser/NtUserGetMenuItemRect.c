/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for NtUserGetMenuItemRect
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "../win32nt.h"

START_TEST(NtUserGetMenuItemRect)
{
    HWND hWnd;
    HMENU hMenu;
    RECT Rect;

    hWnd = CreateWindowW(L"BUTTON", L"Test", WS_OVERLAPPEDWINDOW,
                         0, 0, 100, 100, NULL, NULL, GetModuleHandleW(NULL), NULL);
    hMenu = CreatePopupMenu();
    if (!hWnd || !hMenu)
    {
        skip("Window or menu creation failed\n");
        if (hMenu) DestroyMenu(hMenu);
        if (hWnd) DestroyWindow(hWnd);
        return;
    }
    TEST(AppendMenuW(hMenu, MF_STRING, 100, L"Item") != FALSE);

    /* A buffer of the caller is written */
    TEST(NtUserGetMenuItemRect(hWnd, hMenu, 0, &Rect) != FALSE);

    /* A kernel address is refused and not written */
    SetLastError(ERROR_SUCCESS);
    TEST(NtUserGetMenuItemRect(hWnd, hMenu, 0, (LPRECT)(LONG_PTR)-4096) == FALSE);
    TEST(GetLastError() == ERROR_NOACCESS);

    DestroyMenu(hMenu);
    DestroyWindow(hWnd);
}

/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Test for NtUserCallOneParam
 * PROGRAMMERS:
 */

#include "../win32nt.h"



void
Test_OneParamRoutine_BeginDeferWindowPos(void) /* 0x1e */
{
    HDWP hWinPosInfo;

    hWinPosInfo = (HDWP)NtUserCallOneParam(5, 0x1e);
    TEST(hWinPosInfo != 0);
    TEST(EndDeferWindowPos(hWinPosInfo) != 0);

}

void
Test_OneParamRoutine_WindowFromDC(void) /* 0x1f */
{
    HDC hDC = GetDC(NULL);
    HWND hWnd;

    hWnd = (HWND)NtUserCallOneParam((DWORD)hDC, 0x1f);
    TEST(hWnd != 0);
    TEST(IsWindow(hWnd));
    TEST(hWnd == GetDesktopWindow());

}

void
Test_OneParamRoutine_CreateEmptyCurObject(void) /* XP/2k3 : 0x21, vista 0x25 */
{
    HICON hIcon ;

    /* Test 0 */
    hIcon = (HICON) NtUserCallOneParam(0, _ONEPARAM_ROUTINE_CREATEEMPTYCUROBJECT);
    TEST(hIcon != NULL);

    TEST(NtUserDestroyCursor(hIcon, 0) == TRUE);

    /* Test Garbage */
    hIcon = (HICON) NtUserCallOneParam(0xdeadbeef, _ONEPARAM_ROUTINE_CREATEEMPTYCUROBJECT);
    TEST(hIcon != NULL);

    TEST(NtUserDestroyCursor(hIcon, 0xbaadf00d) == TRUE);

}

void
Test_OneParamRoutine_MapDesktopObject(void) /* 0x30 */
{
    DWORD pObject;
    HWND hWnd;
    HMENU hMenu;

    hWnd = GetDesktopWindow();
    pObject = NtUserCallOneParam((DWORD)hWnd, _ONEPARAM_ROUTINE_MAPDEKTOPOBJECT);
    TEST(pObject > 0);
    TEST(pObject < 0x80000000);

    hMenu = CreateMenu();
    pObject = NtUserCallOneParam((DWORD)hMenu, _ONEPARAM_ROUTINE_MAPDEKTOPOBJECT);
    DestroyMenu(hMenu);
    TEST(pObject > 0);
    TEST(pObject < 0x80000000);

}

void
Test_OneParamRoutine_SwapMouseButtons(void) /* 0x42 */
{
    BOOL bInverse;

    NtUserCallOneParam(TRUE, _ONEPARAM_ROUTINE_SWAPMOUSEBUTTON);
    bInverse = (BOOL)NtUserCallOneParam(FALSE, _ONEPARAM_ROUTINE_SWAPMOUSEBUTTON);
    TEST(bInverse == TRUE);
    bInverse = (BOOL)NtUserCallOneParam(FALSE, _ONEPARAM_ROUTINE_SWAPMOUSEBUTTON);
    TEST(bInverse == FALSE);

    // TODO: test other values
}

void
Test_OneParamRoutine_GetProcDefLayout(void)
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

START_TEST(NtUserCallOneParam)
{
    Test_OneParamRoutine_GetProcDefLayout();
    Test_OneParamRoutine_BeginDeferWindowPos(); /* 0x1e */
    Test_OneParamRoutine_WindowFromDC(); /* 0x1f */
    Test_OneParamRoutine_CreateEmptyCurObject(); /* XP/2k3 : 0x21, vista 0x25 */
    Test_OneParamRoutine_MapDesktopObject(); /* 0x30 */
    Test_OneParamRoutine_SwapMouseButtons(); /* 0x42 */
}

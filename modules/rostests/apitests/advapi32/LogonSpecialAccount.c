/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     LocalService/NetworkService/SYSTEM Service logons are refused for callers without SeTcb
 * COPYRIGHT:   Copyright 2026 Leeway Open Software <281492504+LeewayOpenSoftware@users.noreply.github.com>
 */

#include "precomp.h"

#define CHILD_BASE 100

static
BOOL
HasTcb(VOID)
{
    HANDLE Token;
    BYTE Buffer[2048];
    DWORD Needed, i;
    LUID Tcb;
    PTOKEN_PRIVILEGES Privs = (PTOKEN_PRIVILEGES)Buffer;
    BOOL Found = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return TRUE;
    if (LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Tcb) &&
        GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Needed))
    {
        for (i = 0; i < Privs->PrivilegeCount; i++)
        {
            if (Privs->Privileges[i].Luid.LowPart == Tcb.LowPart && Privs->Privileges[i].Luid.HighPart == Tcb.HighPart)
                Found = TRUE;
        }
    }
    CloseHandle(Token);
    return Found;
}

/* Returns the number of unexpected results (also reported through ok()) */
static
int
TryAccount(PCWSTR Name)
{
    HANDLE Token = NULL;
    BOOL Result;
    DWORD Error;
    int Bad = 0;

    SetLastError(0xdeadbeef);
    Result = LogonUserW(Name, L"NT AUTHORITY", L"", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    Error = GetLastError();
    ok(!Result, "%ls: Service logon without SeTcb succeeded\n", Name);
    ok(Result || Error == ERROR_ACCESS_DENIED, "%ls: error %lu, expected ERROR_ACCESS_DENIED\n", Name, Error);
    if (Result || Error != ERROR_ACCESS_DENIED)
        Bad++;
    if (Result && Token)
        CloseHandle(Token);
    return Bad;
}

static
int
TryAll(VOID)
{
    return TryAccount(L"LocalService") + TryAccount(L"NetworkService");
}

/* A process holding SeTcb (a SYSTEM-run lab) re-runs the check in a child whose token has SeTcb deleted */
static
void
RunWithoutTcb(VOID)
{
    HANDLE Token, Restricted;
    LUID_AND_ATTRIBUTES Delete;
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WCHAR Cmd[MAX_PATH + 32];
    DWORD Exit = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token) ||
        !LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Delete.Luid))
    {
        skip("Cannot prepare a token without SeTcbPrivilege\n");
        return;
    }
    Delete.Attributes = 0;
    if (!CreateRestrictedToken(Token, 0, 0, NULL, 1, &Delete, 0, NULL, &Restricted))
    {
        skip("CreateRestrictedToken failed: %lu\n", GetLastError());
        CloseHandle(Token);
        return;
    }
    CloseHandle(Token);
    GetModuleFileNameW(NULL, Cmd, MAX_PATH);
    wcscat(Cmd, L" LogonSpecialAccount");
    SetEnvironmentVariableW(L"LNT_LSA_CHILD", L"1");
    if (!CreateProcessAsUserW(Restricted, NULL, Cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi))
    {
        skip("CreateProcessAsUser failed: %lu\n", GetLastError());
        CloseHandle(Restricted);
        return;
    }
    WaitForSingleObject(Pi.hProcess, 120000);
    GetExitCodeProcess(Pi.hProcess, &Exit);
    ok(Exit == CHILD_BASE, "child without SeTcb reported exit code %lu (expected %d)\n", Exit, CHILD_BASE);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    CloseHandle(Restricted);
}

START_TEST(LogonSpecialAccount)
{
    WCHAR Flag[8];

    if (GetEnvironmentVariableW(L"LNT_LSA_CHILD", Flag, _countof(Flag)))
    {
        /* Child: exit code CHILD_BASE + number of unexpected results */
        ExitProcess(CHILD_BASE + TryAll());
    }

    if (HasTcb())
    {
        RunWithoutTcb();
        return;
    }

    TryAll();
}

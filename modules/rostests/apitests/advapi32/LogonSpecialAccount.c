/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     LocalService/NetworkService Service logons are refused for callers without SeTcb
 * COPYRIGHT:   Copyright 2026 Leeway Open Software <281492504+LeewayOpenSoftware@users.noreply.github.com>
 */

#include "precomp.h"

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

static
void
TryAccount(PCWSTR Name)
{
    HANDLE Token = NULL;
    BOOL Result;

    SetLastError(0xdeadbeef);
    Result = LogonUserW(Name, L"NT AUTHORITY", L"", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(!Result, "%ls: Service logon without SeTcb succeeded\n", Name);
    if (Result && Token)
        CloseHandle(Token);
}

START_TEST(LogonSpecialAccount)
{
    if (HasTcb())
    {
        skip("The test process holds SeTcbPrivilege\n");
        return;
    }

    TryAccount(L"LocalService");
    TryAccount(L"NetworkService");
}

/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for the umpnpmgr RPC access policy (MUST-7.1): read-only
 *              queries are open to any caller, state-changing requests require
 *              an administrator (CR_ACCESS_DENIED otherwise).
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <apitest.h>
#include <winreg.h>
#include <cfgmgr32.h>

static DEVINST RootDevInst;

/* Representative state-changing call that fires its access gate before any
 * device action, so the restricted-token leg denies it with no side effect. */
static CONFIGRET CallStateChanging(VOID)
{
    /* CM_Reenumerate_DevNode -> PNP_DeviceInstanceAction (gated). */
    return CM_Reenumerate_DevNode(RootDevInst, CM_REENUMERATE_SYNCHRONOUS);
}

/* Representative read-only query (must remain open to any caller). */
static CONFIGRET CallQuery(VOID)
{
    ULONG ulLen = 0;
    /* CM_Get_Device_ID_List_Size -> PNP_GetDeviceListSize (query). */
    return CM_Get_Device_ID_List_Size(&ulLen, NULL, CM_GETIDLIST_FILTER_NONE);
}

static BOOL
IsProcessAdministrator(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID pAdminSid = NULL;
    BOOL bAdmin = FALSE;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid))
        return FALSE;
    if (!CheckTokenMembership(NULL, pAdminSid, &bAdmin))
        bAdmin = FALSE;
    FreeSid(pAdminSid);
    return bAdmin;
}

/* Build an impersonation token with the Administrators alias disabled, so the
 * RPC server sees a non-administrative caller. */
static HANDLE
MakeNonAdminImpersonationToken(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    HANDLE hProcess = NULL, hRestricted = NULL, hImp = NULL;
    PSID pAdminSid = NULL;
    SID_AND_ATTRIBUTES Disable;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hProcess))
        return NULL;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid))
    {
        Disable.Sid = pAdminSid;
        Disable.Attributes = 0;
        if (CreateRestrictedToken(hProcess, 0, 1, &Disable, 0, NULL, 0, NULL, &hRestricted))
        {
            DuplicateToken(hRestricted, SecurityImpersonation, &hImp);
            CloseHandle(hRestricted);
        }
        FreeSid(pAdminSid);
    }

    CloseHandle(hProcess);
    return hImp;
}

START_TEST(PnpAccessPolicy)
{
    CONFIGRET cr;
    HANDLE hImp;
    BOOL bAdmin;

    cr = CM_Locate_DevNodeW(&RootDevInst, (DEVINSTID_W)L"HTREE\\ROOT\\0", CM_LOCATE_DEVNODE_NORMAL);
    ok(cr == CR_SUCCESS, "CM_Locate_DevNodeW(HTREE\\ROOT\\0) returned %lu\n", cr);
    if (cr != CR_SUCCESS)
        return;

    bAdmin = IsProcessAdministrator();

    /* As the process token: an administrator must NOT be denied the state change. */
    if (bAdmin)
    {
        cr = CallStateChanging();
        ok(cr != CR_ACCESS_DENIED,
           "Administrator state-changing call returned CR_ACCESS_DENIED (%lu); the gate must let admins through\n", cr);
    }
    else
    {
        skip("Not running as administrator; skipping the positive (admin) leg\n");
    }

    /* The query must always succeed, regardless of caller rights. */
    cr = CallQuery();
    ok(cr == CR_SUCCESS, "Query (CM_Get_Device_ID_List_Size) returned %lu, expected CR_SUCCESS\n", cr);

    /* As a non-administrative (Administrators-disabled) token the state-changing
     * call must be denied, and the query must still succeed. */
    hImp = MakeNonAdminImpersonationToken();
    if (hImp == NULL)
    {
        skip("Could not build a non-admin impersonation token (err %lu); skipping the denial leg\n",
             GetLastError());
        return;
    }

    if (!SetThreadToken(NULL, hImp))
    {
        skip("SetThreadToken failed (err %lu); skipping the denial leg\n", GetLastError());
        CloseHandle(hImp);
        return;
    }

    cr = CallStateChanging();
    ok(cr == CR_ACCESS_DENIED,
       "Non-admin state-changing call returned %lu, expected CR_ACCESS_DENIED\n", cr);

    cr = CallQuery();
    ok(cr == CR_SUCCESS,
       "Non-admin query returned %lu, expected CR_SUCCESS (queries stay open)\n", cr);

    SetThreadToken(NULL, NULL);
    CloseHandle(hImp);
}

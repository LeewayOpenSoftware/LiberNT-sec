/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     winlogon's secure-desktop prompt interface answers nobody but the broker
 */

#include "precomp.h"

#include <rpc.h>
#include <strsafe.h>
#include <wlsecdesk_c.h>

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR *ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

static DWORD CallBegin(handle_t hBinding, DWORD Timeout)
{
    DWORD Error;

    RpcTryExcept
    {
        Error = WlSecureDesktopBegin(hBinding, Timeout);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = RpcExceptionCode();
    }
    RpcEndExcept;
    return Error;
}

static DWORD CallEnd(handle_t hBinding)
{
    DWORD Error;

    RpcTryExcept
    {
        Error = WlSecureDesktopEnd(hBinding);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = RpcExceptionCode();
    }
    RpcEndExcept;
    return Error;
}

START_TEST(SecureDesktop)
{
    WCHAR Endpoint[64];
    DWORD SessionId = 0, Error;
    RPC_WSTR StringBinding = NULL;
    handle_t hBinding = NULL;

    ProcessIdToSessionId(GetCurrentProcessId(), &SessionId);
    StringCchPrintfW(Endpoint, _countof(Endpoint), L"wlsecdesk-%lu", SessionId);

    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)Endpoint, NULL, &StringBinding) != RPC_S_OK ||
        RpcBindingFromStringBindingW(StringBinding, &hBinding) != RPC_S_OK)
    {
        skip("No binding to %ls\n", Endpoint);
        if (StringBinding) RpcStringFreeW(&StringBinding);
        return;
    }
    RpcStringFreeW(&StringBinding);

    /* This process is not the broker, whatever account runs the test */
    Error = CallBegin(hBinding, 5000);
    if (Error == RPC_S_SERVER_UNAVAILABLE || Error == EPT_S_NOT_REGISTERED)
    {
        skip("The winlogon of session %lu has no secure-desktop endpoint\n", SessionId);
        RpcBindingFree(&hBinding);
        return;
    }
    ok(Error == ERROR_ACCESS_DENIED, "Begin from a plain process: %lu\n", Error);

    Error = CallEnd(hBinding);
    ok(Error == ERROR_ACCESS_DENIED, "End from a plain process: %lu\n", Error);

    /* A refused Begin left no state behind: the next one is refused the same way, not busy */
    Error = CallBegin(hBinding, 5000);
    ok(Error == ERROR_ACCESS_DENIED, "Second Begin from a plain process: %lu\n", Error);

    /* A bad timeout is still a refusal of the caller first */
    Error = CallBegin(hBinding, 0);
    ok(Error == ERROR_ACCESS_DENIED, "Begin with timeout 0 from a plain process: %lu\n", Error);

    RpcBindingFree(&hBinding);
}

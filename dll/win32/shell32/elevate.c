/*
 * PROJECT:     LiberNT shell32
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Asks the secondary logon service to start a program elevated
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <winsvc.h>
#include <rpc.h>
#include "seclogon_c.h"

/* kernel32 exports it (Vista+); the SDK header hides it behind a version guard */
BOOL WINAPI GetNamedPipeServerProcessId(HANDLE Pipe, PULONG ServerProcessId);

/* The process at the other end of the pipe must be the secondary logon service host as the
 * service control manager reports it, before anything travels to it: a program that created
 * the name before the service would receive the clients. Every caller may ask the SCM; no
 * handle to the SYSTEM process is needed. ERROR_SERVICE_NOT_ACTIVE when the service is not
 * running or the pipe is absent, ERROR_ACCESS_DENIED when another process holds the name. */
static
DWORD
SeclCheckServer(VOID)
{
    SC_HANDLE hScm, hService;
    SERVICE_STATUS_PROCESS Status;
    HANDLE hPipe;
    DWORD Needed, ServicePid = 0, ServerPid = 0;

    /* The pipe first: whoever holds the name now is judged against a service that is
     * running now under that very pid, which a reused pid of a dead service cannot be */
    hPipe = CreateFileW(L"\\\\.\\pipe\\seclogon", GENERIC_READ, 0, NULL, OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (hPipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(L"\\\\.\\pipe\\seclogon", 2000))
    {
        hPipe = CreateFileW(L"\\\\.\\pipe\\seclogon", GENERIC_READ, 0, NULL, OPEN_EXISTING,
                            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    }
    if (hPipe == INVALID_HANDLE_VALUE)
        return ERROR_SERVICE_NOT_ACTIVE;
    if (!GetNamedPipeServerProcessId(hPipe, &ServerPid))
        ServerPid = 0;
    CloseHandle(hPipe);
    if (ServerPid == 0)
        return ERROR_ACCESS_DENIED;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
        return ERROR_SERVICE_NOT_ACTIVE;
    hService = OpenServiceW(hScm, L"seclogon", SERVICE_QUERY_STATUS);
    if (hService != NULL)
    {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_RUNNING)
        {
            ServicePid = Status.dwProcessId;
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hScm);
    if (ServicePid == 0)
        return ERROR_SERVICE_NOT_ACTIVE;

    return (ServerPid == ServicePid) ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

/* ERROR_ELEVATION_REQUIRED: no broker path for this caller (standard user, credential
 * policy, LUA off); ERROR_CANCELLED: the user said no; ERROR_SERVICE_NOT_ACTIVE: no broker. */
DWORD
SHELL_ElevateProcess(
    _In_opt_ HWND hwnd,
    _In_opt_ LPCWSTR ApplicationName,
    _In_opt_ LPCWSTR CommandLine,
    _In_opt_ LPCWSTR CurrentDirectory,
    _In_ DWORD CreationFlags,
    _In_opt_ const STARTUPINFOW *pStartupInfo,
    _Out_ PROCESS_INFORMATION *pProcessInfo)
{
    SECL_ELEVATE_REQUEST Request = { 0 };
    SECL_RESPONSE Response = { 0 };
    RPC_WSTR StringBinding = NULL;
    handle_t hBinding = NULL;
    DWORD dwError;

    ZeroMemory(pProcessInfo, sizeof(*pProcessInfo));

    Request.ApplicationName = (WCHAR *)ApplicationName;
    Request.CommandLine = (WCHAR *)CommandLine;
    Request.CurrentDirectory = (WCHAR *)CurrentDirectory;
    if (pStartupInfo != NULL && pStartupInfo->lpDesktop != NULL && pStartupInfo->lpDesktop[0] != UNICODE_NULL)
        Request.Desktop = pStartupInfo->lpDesktop;
    Request.dwDesktopInherited = (Request.Desktop == NULL);
    Request.dwCreationFlags = CreationFlags;
    Request.dwShowCmd = (pStartupInfo != NULL && (pStartupInfo->dwFlags & STARTF_USESHOWWINDOW))
                        ? pStartupInfo->wShowWindow : SW_SHOWNORMAL;
    Request.hwndOwner = (DWORD_PTR)hwnd;

    {
        DWORD Check = SeclCheckServer();
        if (Check != ERROR_SUCCESS)
            return Check;
    }

    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_np", NULL, (RPC_WSTR)L"\\pipe\\seclogon",
                                 NULL, &StringBinding) != RPC_S_OK)
    {
        return ERROR_SERVICE_NOT_ACTIVE;
    }
    if (RpcBindingFromStringBindingW(StringBinding, &hBinding) != RPC_S_OK)
    {
        RpcStringFreeW(&StringBinding);
        return ERROR_SERVICE_NOT_ACTIVE;
    }
    RpcStringFreeW(&StringBinding);

    RpcTryExcept
    {
        SeclCreateProcessElevatedW(hBinding, &Request, &Response);
        dwError = Response.dwError;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RpcExceptionCode();
    }
    RpcEndExcept;

    RpcBindingFree(&hBinding);

    if (dwError == ERROR_SUCCESS)
    {
        pProcessInfo->hProcess = (HANDLE)Response.hProcess;
        pProcessInfo->hThread = (HANDLE)Response.hThread;
        pProcessInfo->dwProcessId = Response.dwProcessId;
        pProcessInfo->dwThreadId = Response.dwThreadId;
    }
    else if (dwError == RPC_S_SERVER_UNAVAILABLE || dwError == EPT_S_NOT_REGISTERED ||
             dwError == RPC_S_PROCNUM_OUT_OF_RANGE)
    {
        dwError = ERROR_SERVICE_NOT_ACTIVE;
    }
    return dwError;
}

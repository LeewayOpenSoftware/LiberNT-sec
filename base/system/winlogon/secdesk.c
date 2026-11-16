/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Winlogon
 * FILE:            base/system/winlogon/secdesk.c
 * PURPOSE:         Secure-desktop prompt state for the elevation broker (RPC server side)
 */

/* INCLUDES ******************************************************************/

#include "winlogon.h"

#include <rpc.h>
#include <winsvc.h>
#include <wlsecdesk_s.h>

/* GLOBALS *******************************************************************/

/* The broker has at most this long after Begin before winlogon returns alone */
#define SECDESK_MAX_TIMEOUT_MS (5 * 60 * 1000)

static CRITICAL_SECTION SecDeskLock;

/* FUNCTIONS *****************************************************************/

/* The process id of the running secondary logon service, 0 when it is not running */
static
DWORD
SecDeskServicePid(VOID)
{
    SC_HANDLE hScm, hService;
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Pid = 0;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm)
        return 0;

    hService = OpenServiceW(hScm, L"seclogon", SERVICE_QUERY_STATUS);
    if (hService)
    {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_RUNNING)
        {
            Pid = Status.dwProcessId;
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hScm);
    return Pid;
}

/* Only the broker is heard: the caller runs as SYSTEM and is the service process.
 * Both facts come from the runtime and the system, not from the request. */
static
DWORD
SecDeskCheckCaller(
    _In_ handle_t hBinding,
    _Out_ PDWORD pClientPid)
{
    BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    ULONG ClientPid = 0;
    HANDLE hToken;
    DWORD Length;
    BOOL IsSystem = FALSE;

    *pClientPid = 0;

    if (I_RpcBindingInqLocalClientPID(hBinding, &ClientPid) != RPC_S_OK || ClientPid == 0)
        return ERROR_ACCESS_DENIED;

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
        return ERROR_ACCESS_DENIED;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
    {
        if (GetTokenInformation(hToken, TokenUser, User, sizeof(Buffer), &Length))
            IsSystem = IsWellKnownSid(User->User.Sid, WinLocalSystemSid);
        CloseHandle(hToken);
    }

    RpcRevertToSelf();

    if (!IsSystem)
        return ERROR_ACCESS_DENIED;

    if (ClientPid != SecDeskServicePid())
        return ERROR_ACCESS_DENIED;

    *pClientPid = ClientPid;
    return ERROR_SUCCESS;
}

/* Called with SecDeskLock held */
static
VOID
SecDeskClear(
    _Inout_ PWLSESSION Session)
{
    if (Session->SecurePromptBroker)
        CloseHandle(Session->SecurePromptBroker);
    Session->SecurePromptBroker = NULL;
    Session->SecurePromptBrokerPid = 0;
    Session->SecurePromptTimeoutMs = 0;
    Session->SecurePromptStart = 0;
}

BOOL
StartSecureDesktopServer(VOID)
{
    WCHAR Endpoint[64];
    DWORD SessionId = 0;
    RPC_STATUS Status;

    InitializeCriticalSection(&SecDeskLock);

    /* One endpoint per session, so the broker reaches the winlogon of the caller's session */
    ProcessIdToSessionId(GetCurrentProcessId(), &SessionId);
    StringCchPrintfW(Endpoint, _countof(Endpoint), L"wlsecdesk-%lu", SessionId);

    Status = RpcServerUseProtseqEpW(L"ncalrpc",
                                    RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                    Endpoint,
                                    NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerUseProtseqEpW(%S) failed (Status %lx)\n", Endpoint, Status);
        return FALSE;
    }

    Status = RpcServerRegisterIfEx(IWlSecureDesktop_v1_0_s_ifspec,
                                   NULL,
                                   NULL,
                                   RPC_IF_ALLOW_LOCAL_ONLY,
                                   RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                   NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerRegisterIfEx(wlsecdesk) failed (Status %lx)\n", Status);
        return FALSE;
    }

    TRACE("Secure-desktop endpoint %S registered\n", Endpoint);
    return TRUE;
}

/* Function 0 */
error_status_t
__stdcall
WlSecureDesktopBegin(
    handle_t hBinding,
    DWORD dwTimeoutMs)
{
    PWLSESSION Session = WLSession;
    HANDLE hBroker;
    DWORD Pid, Error;

    Error = SecDeskCheckCaller(hBinding, &Pid);
    if (Error != ERROR_SUCCESS)
    {
        ERR("Secure-desktop Begin refused: Error %lu\n", Error);
        return Error;
    }

    if (dwTimeoutMs == 0 || dwTimeoutMs > SECDESK_MAX_TIMEOUT_MS)
        return ERROR_INVALID_PARAMETER;

    /* The broker's process is what tells winlogon later that the broker is gone */
    hBroker = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hBroker)
        return ERROR_ACCESS_DENIED;

    EnterCriticalSection(&SecDeskLock);

    /* A prompt whose broker has died is over */
    if (Session->SecurePromptBroker &&
        WaitForSingleObject(Session->SecurePromptBroker, 0) == WAIT_OBJECT_0)
    {
        ERR("Secure-desktop prompt of broker %lu ended with its process\n", Session->SecurePromptBrokerPid);
        SecDeskClear(Session);
    }

    if (Session->SecurePromptBroker)
    {
        LeaveCriticalSection(&SecDeskLock);
        CloseHandle(hBroker);
        ERR("Secure-desktop Begin from %lu while a prompt is up\n", Pid);
        return ERROR_BUSY;
    }

    Session->SecurePromptBroker = hBroker;
    Session->SecurePromptBrokerPid = Pid;
    Session->SecurePromptTimeoutMs = dwTimeoutMs;
    Session->SecurePromptStart = GetTickCount();

    LeaveCriticalSection(&SecDeskLock);

    TRACE("Secure-desktop prompt begun by %lu, %lu ms\n", Pid, dwTimeoutMs);
    return ERROR_SUCCESS;
}

/* Function 1 */
error_status_t
__stdcall
WlSecureDesktopEnd(
    handle_t hBinding)
{
    PWLSESSION Session = WLSession;
    DWORD Pid, Error;

    Error = SecDeskCheckCaller(hBinding, &Pid);
    if (Error != ERROR_SUCCESS)
    {
        ERR("Secure-desktop End refused: Error %lu\n", Error);
        return Error;
    }

    EnterCriticalSection(&SecDeskLock);

    if (!Session->SecurePromptBroker)
    {
        LeaveCriticalSection(&SecDeskLock);
        return ERROR_INVALID_STATE;
    }

    if (Session->SecurePromptBrokerPid != Pid)
    {
        LeaveCriticalSection(&SecDeskLock);
        ERR("Secure-desktop End from %lu for the prompt of %lu\n", Pid, Session->SecurePromptBrokerPid);
        return ERROR_ACCESS_DENIED;
    }

    SecDeskClear(Session);

    LeaveCriticalSection(&SecDeskLock);

    TRACE("Secure-desktop prompt of %lu ended\n", Pid);
    return ERROR_SUCCESS;
}

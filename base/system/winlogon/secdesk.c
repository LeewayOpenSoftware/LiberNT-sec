/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Winlogon
 * FILE:            base/system/winlogon/secdesk.c
 * PURPOSE:         Secure-desktop prompt held for the elevation broker (RPC server side)
 */

/* INCLUDES ******************************************************************/

#include "winlogon.h"

#include <rpc.h>
#include <winsvc.h>
#include <wlsecdesk_s.h>

/* user32 exports both; the SDK headers declare neither */
BOOL WINAPI LockWindowStation(HWINSTA hWinSta);
BOOL WINAPI UnlockWindowStation(HWINSTA hWinSta);

/* GLOBALS *******************************************************************/

/* The broker's timeout: at least a few seconds (a prompt needs that long to be seen),
 * at most this long after Begin before winlogon returns alone */
#define SECDESK_MIN_TIMEOUT_MS   (5 * 1000)
#define SECDESK_MAX_TIMEOUT_MS   (5 * 60 * 1000)
/* The prompt thread has this long to switch before Begin gives up */
#define SECDESK_SWITCH_WAIT_MS   (10 * 1000)
/* Slack on top of the broker's timeout before winlogon returns alone */
#define SECDESK_WATCHDOG_SLACK_MS (10 * 1000)

static CRITICAL_SECTION SecDeskLock;
/* Signalled while no prompt is held; the SAS, lock and logoff paths wait on it */
static HANDLE SecDeskIdleEvent;
static const WCHAR SecDeskBackdropClass[] = L"WinlogonSecurePromptBackdrop";

/* What the prompt thread works with. Shared by Begin and the thread through a
 * reference count; the session state it stands behind is cleared by the thread
 * alone once the thread runs. */
typedef struct _SECDESK_PROMPT
{
    LONG Refs;
    PWLSESSION Session;
    HANDLE hBroker;     /* the broker's process: its end ends the prompt */
    HANDLE hEnd;        /* set by End, or by Begin when it gave up waiting */
    HANDLE hReady;      /* set by the thread once switched, or once it gave up */
    DWORD TimeoutMs;
    DWORD Generation;   /* the session's generation when this prompt took the slot */
    BOOL Switched;
} SECDESK_PROMPT, *PSECDESK_PROMPT;

/* FUNCTIONS *****************************************************************/

/* The process id of the running secondary logon service host, 0 when it is not running */
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

/* Only the broker is heard: the caller runs as SYSTEM and is the service host process.
 * Both facts come from the runtime and the system, not from the request. This is the
 * whole protection: the runtime enforces no local-only flag and the endpoint's pipe is
 * open to every local caller. */
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
    if (Session->SecurePromptEnd)
        CloseHandle(Session->SecurePromptEnd);
    Session->SecurePromptBroker = NULL;
    Session->SecurePromptEnd = NULL;
    Session->SecurePromptBrokerPid = 0;
    Session->SecurePromptTimeoutMs = 0;
    Session->SecurePromptStart = 0;
    Session->SecurePromptGeneration++;
    SetEvent(SecDeskIdleEvent);
}

static
VOID
SecDeskPromptRelease(
    _In_ PSECDESK_PROMPT Prompt)
{
    if (InterlockedDecrement(&Prompt->Refs) == 0)
    {
        CloseHandle(Prompt->hReady);
        HeapFree(GetProcessHeap(), 0, Prompt);
    }
}

static
LRESULT
CALLBACK
SecDeskBackdropProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_ERASEBKGND:
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect((HDC)wParam, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            return 1;
        }
        case WM_CLOSE:
            /* Only the prompt thread takes it down */
            return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

/* The one way back, used by every path: the backdrop goes, the user's desktop
 * returns, the window station is unlocked. Each step is tried even if the one
 * before failed, so nothing stays half done. The unlock is unconditional because
 * nothing else in winlogon locks the window station today (sas.c, winlogon.c,
 * wlx.c); the day the lock screen uses that lock, the previous state must be
 * kept and restored here instead. */
static
VOID
SecDeskReturn(
    _In_ PWLSESSION Session,
    _In_opt_ HWND hwndBackdrop)
{
    BOOL SwitchBack;

    if (hwndBackdrop)
        DestroyWindow(hwndBackdrop);

    /* The user's desktop comes back only while the session is still logged on and
     * unlocked; after a lock, a SAS or a logoff the desktop stays where the SAS code
     * put it (it switches back itself when its dialog ends) */
    EnterCriticalSection(&SecDeskLock);
    SwitchBack = (Session->LogonState == STATE_LOGGED_ON);
    LeaveCriticalSection(&SecDeskLock);
    if (!SwitchBack)
        ERR("Secure-desktop return: the session is no longer logged on and unlocked, the desktop stays\n");
    else if (!SwitchDesktop(Session->ApplicationDesktop))
        ERR("Secure-desktop return: SwitchDesktop failed (error %lu)\n", GetLastError());
    if (!UnlockWindowStation(Session->InteractiveWindowStation))
        ERR("Secure-desktop return: UnlockWindowStation failed (error %lu)\n", GetLastError());
}

/* One thread per prompt: it owns the backdrop window, holds the switch, and
 * returns when the broker says End, when the broker's process ends, or when
 * the broker's own timeout plus slack has passed. On every path, success or
 * failure, this thread is the one that clears the session state. */
static
DWORD
WINAPI
SecDeskPromptThread(
    _In_ LPVOID Parameter)
{
    PSECDESK_PROMPT Prompt = (PSECDESK_PROMPT)Parameter;
    PWLSESSION Session = Prompt->Session;
    HANDLE Handles[2] = { Prompt->hEnd, Prompt->hBroker };
    HWND hwndBackdrop = NULL;
    DWORD Start, Elapsed, Wait, Result;
    MSG msg;

    /* Everything below happens on the Winlogon desktop */
    if (!SetThreadDesktop(Session->WinlogonDesktop))
    {
        ERR("Secure-desktop prompt: SetThreadDesktop failed (error %lu)\n", GetLastError());
        goto Failed;
    }

    /* Not topmost: the prompt the broker starts afterwards must come above it.
     * Never activated: it must not take the keyboard from the prompt. */
    hwndBackdrop = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                                   SecDeskBackdropClass, L"",
                                   WS_POPUP,
                                   0, 0,
                                   GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
                                   NULL, NULL, hAppInstance, NULL);
    if (!hwndBackdrop)
    {
        ERR("Secure-desktop prompt: backdrop window failed (error %lu)\n", GetLastError());
        goto Failed;
    }

    /* Lock first, so that nobody switches back under the prompt; only the logon process may */
    if (!LockWindowStation(Session->InteractiveWindowStation))
    {
        ERR("Secure-desktop prompt: LockWindowStation failed (error %lu)\n", GetLastError());
        DestroyWindow(hwndBackdrop);
        goto Failed;
    }

    if (!SwitchDesktop(Session->WinlogonDesktop))
    {
        ERR("Secure-desktop prompt: SwitchDesktop failed (error %lu)\n", GetLastError());
        SecDeskReturn(Session, hwndBackdrop);
        goto Failed;
    }

    ShowWindow(hwndBackdrop, SW_SHOWNA);
    UpdateWindow(hwndBackdrop);

    Prompt->Switched = TRUE;
    SetEvent(Prompt->hReady);

    Start = GetTickCount();
    for (;;)
    {
        Elapsed = GetTickCount() - Start;
        if (Elapsed >= Prompt->TimeoutMs + SECDESK_WATCHDOG_SLACK_MS)
        {
            ERR("Secure-desktop prompt: the broker did not end it in time, returning alone\n");
            break;
        }
        Wait = Prompt->TimeoutMs + SECDESK_WATCHDOG_SLACK_MS - Elapsed;

        Result = MsgWaitForMultipleObjects(2, Handles, FALSE, Wait, QS_ALLINPUT);
        if (Result == WAIT_OBJECT_0)
        {
            TRACE("Secure-desktop prompt: End received\n");
            break;
        }
        if (Result == WAIT_OBJECT_0 + 1)
        {
            ERR("Secure-desktop prompt: the broker's process ended, returning alone\n");
            break;
        }
        if (Result == WAIT_OBJECT_0 + 2)
        {
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            continue;
        }
        /* Timeout or failure of the wait itself: return either way */
        break;
    }

    SecDeskReturn(Session, hwndBackdrop);

    EnterCriticalSection(&SecDeskLock);
    SecDeskClear(Session);
    LeaveCriticalSection(&SecDeskLock);

    SecDeskPromptRelease(Prompt);
    return 0;

Failed:
    /* Nothing is held. The state is ours to clear, then Begin may read the answer. */
    EnterCriticalSection(&SecDeskLock);
    SecDeskClear(Session);
    LeaveCriticalSection(&SecDeskLock);

    Prompt->Switched = FALSE;
    SetEvent(Prompt->hReady);
    SecDeskPromptRelease(Prompt);
    return 0;
}

/* A lock, a logoff or a SAS that arrives while a prompt is up ends the prompt and
 * waits until the prompt thread has returned, so that its own switch is not undone
 * by the thread's return a moment later. Returns at once when no prompt is held. */
VOID
SecDeskEndPromptAndWait(
    _In_ PWLSESSION Session)
{
    if (!SecDeskIdleEvent)
        return;

    EnterCriticalSection(&SecDeskLock);
    /* Held until the caller's action is done (SecDeskReleaseHold): Begin refuses meanwhile */
    Session->SecurePromptHold++;
    if (Session->SecurePromptBroker)
    {
        ERR("Secure-desktop prompt of %lu ended by the session (SAS, lock or logoff)\n", Session->SecurePromptBrokerPid);
        SetEvent(Session->SecurePromptEnd);
    }
    LeaveCriticalSection(&SecDeskLock);

    /* The thread returns within the broker's timeout plus slack at the latest */
    if (WaitForSingleObject(SecDeskIdleEvent, SECDESK_MAX_TIMEOUT_MS + 2 * SECDESK_WATCHDOG_SLACK_MS) != WAIT_OBJECT_0)
        ERR("Secure-desktop prompt thread did not return; going on\n");
}

/* The SAS, lock or logoff action that called SecDeskEndPromptAndWait is done */
VOID
SecDeskReleaseHold(
    _In_ PWLSESSION Session)
{
    if (!SecDeskIdleEvent)
        return;
    EnterCriticalSection(&SecDeskLock);
    if (Session->SecurePromptHold > 0)
        Session->SecurePromptHold--;
    LeaveCriticalSection(&SecDeskLock);
}

BOOL
StartSecureDesktopServer(VOID)
{
    WNDCLASSEXW wc = { sizeof(wc) };
    WCHAR Endpoint[64];
    DWORD SessionId = 0;
    RPC_STATUS Status;

    InitializeCriticalSection(&SecDeskLock);
    SecDeskIdleEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (!SecDeskIdleEvent)
    {
        ERR("Secure-desktop idle event failed (error %lu); no secure-desktop prompts in this session\n", GetLastError());
        return TRUE;
    }

    wc.lpfnWndProc = SecDeskBackdropProc;
    wc.hInstance = hAppInstance;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = SecDeskBackdropClass;
    if (!RegisterClassExW(&wc))
        ERR("Secure-desktop backdrop class failed (error %lu)\n", GetLastError());

    /* One endpoint per session, so the broker reaches the winlogon of the caller's session.
     * The runtime does not honour a security descriptor for ncalrpc (RpcServerUseProtseqEpExW
     * drops it), so the callers are checked inside the functions instead. A failure here is
     * not fatal: without the endpoint the broker gets no Begin and refuses the elevation. */
    ProcessIdToSessionId(GetCurrentProcessId(), &SessionId);
    StringCchPrintfW(Endpoint, _countof(Endpoint), L"wlsecdesk-%lu", SessionId);

    Status = RpcServerUseProtseqEpW(L"ncalrpc",
                                    RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                    Endpoint,
                                    NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerUseProtseqEpW(%S) failed (Status %lx); no secure-desktop prompts in this session\n", Endpoint, Status);
        return TRUE;
    }

    Status = RpcServerRegisterIfEx(IWlSecureDesktop_v1_0_s_ifspec,
                                   NULL,
                                   NULL,
                                   RPC_IF_ALLOW_LOCAL_ONLY,
                                   RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                   NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerRegisterIfEx(wlsecdesk) failed (Status %lx); no secure-desktop prompts in this session\n", Status);
        return TRUE;
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
    PSECDESK_PROMPT Prompt;
    HANDLE hBroker, hEnd, hReady, hThread;
    DWORD Pid, Error;
    BOOL Switched;

    Error = SecDeskCheckCaller(hBinding, &Pid);
    if (Error != ERROR_SUCCESS)
    {
        ERR("Secure-desktop Begin refused: Error %lu\n", Error);
        return Error;
    }

    if (!SecDeskIdleEvent)
        return ERROR_NOT_READY;

    if (dwTimeoutMs < SECDESK_MIN_TIMEOUT_MS || dwTimeoutMs > SECDESK_MAX_TIMEOUT_MS)
        return ERROR_INVALID_PARAMETER;

    /* The broker's process is what tells the prompt thread that the broker is gone */
    hBroker = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hBroker)
        return ERROR_ACCESS_DENIED;

    hEnd = CreateEventW(NULL, TRUE, FALSE, NULL);
    hReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    Prompt = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Prompt));
    if (!hEnd || !hReady || !Prompt)
    {
        if (hEnd) CloseHandle(hEnd);
        if (hReady) CloseHandle(hReady);
        if (Prompt) HeapFree(GetProcessHeap(), 0, Prompt);
        CloseHandle(hBroker);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    EnterCriticalSection(&SecDeskLock);

    /* Only a logged-on, unlocked session gets a prompt: the return switches to the
     * user's desktop and unlocks the window station, which must never undo a lock,
     * a logon dialog or the screen saver. Read as the SAS code reads it. */
    if (Session->LogonState != STATE_LOGGED_ON || Session->SecurePromptHold != 0)
    {
        LeaveCriticalSection(&SecDeskLock);
        CloseHandle(hEnd);
        CloseHandle(hReady);
        HeapFree(GetProcessHeap(), 0, Prompt);
        CloseHandle(hBroker);
        ERR("Secure-desktop Begin from %lu refused: the session is not logged on and unlocked (state %d)\n", Pid, Session->LogonState);
        return ERROR_NOT_READY;
    }

    if (Session->SecurePromptBroker)
    {
        LeaveCriticalSection(&SecDeskLock);
        CloseHandle(hEnd);
        CloseHandle(hReady);
        HeapFree(GetProcessHeap(), 0, Prompt);
        CloseHandle(hBroker);
        ERR("Secure-desktop Begin from %lu while a prompt is up\n", Pid);
        return ERROR_BUSY;
    }

    Session->SecurePromptBroker = hBroker;
    Session->SecurePromptEnd = hEnd;
    Session->SecurePromptBrokerPid = Pid;
    Session->SecurePromptTimeoutMs = dwTimeoutMs;
    Session->SecurePromptStart = GetTickCount();
    ResetEvent(SecDeskIdleEvent);
    Prompt->Generation = Session->SecurePromptGeneration;

    LeaveCriticalSection(&SecDeskLock);

    Prompt->Refs = 2; /* this call and the thread */
    Prompt->Session = Session;
    Prompt->hBroker = hBroker;
    Prompt->hEnd = hEnd;
    Prompt->hReady = hReady;
    Prompt->TimeoutMs = dwTimeoutMs;

    hThread = CreateThread(NULL, 0, SecDeskPromptThread, Prompt, 0, NULL);
    if (!hThread)
    {
        /* No thread: this call owns everything */
        ERR("Secure-desktop prompt thread could not be created (error %lu)\n", GetLastError());
        EnterCriticalSection(&SecDeskLock);
        SecDeskClear(Session);
        LeaveCriticalSection(&SecDeskLock);
        CloseHandle(hReady);
        HeapFree(GetProcessHeap(), 0, Prompt);
        return ERROR_GEN_FAILURE;
    }
    CloseHandle(hThread);

    /* From here the thread owns the session state. This call only reads the
     * answer once it is there and drops its reference. */
    if (WaitForSingleObject(hReady, SECDESK_SWITCH_WAIT_MS) == WAIT_OBJECT_0)
    {
        Switched = Prompt->Switched;
    }
    else
    {
        /* The thread is late: tell it to return as soon as it has switched; the
         * slot stays busy until it has really returned, the desktop may still be
         * switched for a moment */
        ERR("Secure-desktop prompt thread did not switch in time\n");
        EnterCriticalSection(&SecDeskLock);
        if (Session->SecurePromptBroker && Session->SecurePromptGeneration == Prompt->Generation)
            SetEvent(Session->SecurePromptEnd);
        LeaveCriticalSection(&SecDeskLock);
        Switched = FALSE;
    }
    SecDeskPromptRelease(Prompt);

    if (!Switched)
    {
        ERR("Secure-desktop Begin from %lu: the switch failed, the request is refused\n", Pid);
        return ERROR_GEN_FAILURE;
    }

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
        /* A broker that has ended cannot end its prompt; the thread returns on its own,
         * and a restarted service must not find a state it can never end */
        if (WaitForSingleObject(Session->SecurePromptBroker, 0) == WAIT_OBJECT_0)
        {
            LeaveCriticalSection(&SecDeskLock);
            return ERROR_INVALID_STATE;
        }
        LeaveCriticalSection(&SecDeskLock);
        ERR("Secure-desktop End from %lu for the prompt of %lu\n", Pid, Session->SecurePromptBrokerPid);
        return ERROR_ACCESS_DENIED;
    }

    /* The prompt thread does the return and clears the state */
    SetEvent(Session->SecurePromptEnd);

    LeaveCriticalSection(&SecDeskLock);

    TRACE("Secure-desktop prompt of %lu ending\n", Pid);
    return ERROR_SUCCESS;
}

/*
 * PROJECT:     LiberNT tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Checks that a limited process cannot steer the elevation prompt
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 *
 * Run it as the limited side of a split administrator logon, with EnableLUA=1 and a
 * consent mode of ConsentPromptBehaviorAdmin. It needs no administrator rights.
 *
 *   uacprobe n     the broker refuses a desktop other than the caller's default one (error 740 or 5)
 *   uacprobe p     messages, input, hooks and window calls do not reach the prompt
 *   uacprobe       both
 *
 * Each check prints one line starting with PASS or FAIL. Check p leaves the prompt
 * open: answer it with No (or let it time out). The exit code is the number of FAIL
 * lines, or 100 when the program could not run its checks.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <winreg.h>
#include <rpc.h>
#include <pseh/pseh2.h>
#include <seclogon_c.h>

#ifndef TokenElevationTypeLimited
#define TokenElevationTypeLimited 3
#endif

#define CONSENT_TITLE   L"User Account Control"
#define CONSENT_CLASS   L"#32770"
#define APPEAR_MS       15000
#define SETTLE_MS       1500
#define ANSWER_MS       150000

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

typedef struct _BROKER_CALL
{
    PCWSTR Desktop;             /* NULL: the caller's own desktop */
    DWORD Error;
    SECL_RESPONSE Response;
} BROKER_CALL;

static int g_Failures;
static HWND g_Consent;
static LONG g_KeysSeen;
static LONG g_MouseSeen;

static void Report(BOOL Passed, const char *Format, ...)
{
    va_list Args;

    if (!Passed)
        g_Failures++;
    printf("%s: ", Passed ? "PASS" : "FAIL");
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
    printf("\n");
    fflush(stdout);
}

static void Info(const char *Format, ...)
{
    va_list Args;

    printf("INFO: ");
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
    printf("\n");
    fflush(stdout);
}

static BOOL IsLimitedCaller(void)
{
    HANDLE Token;
    DWORD Type = 0, Length;
    BOOL Limited = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenElevationType, &Type, sizeof(Type), &Length))
            Limited = (Type == TokenElevationTypeLimited);
        CloseHandle(Token);
    }
    return Limited;
}

/* The broker call blocks until the prompt is answered, so it runs on its own thread */
static DWORD WINAPI BrokerThread(LPVOID Parameter)
{
    BROKER_CALL *Call = Parameter;
    SECL_ELEVATE_REQUEST Request = { 0 };
    WCHAR Image[MAX_PATH], CommandLine[MAX_PATH + 16];
    UINT Length;
    RPC_WSTR StringBinding = NULL;
    handle_t Binding = NULL;

    /* A harmless program by its full path: if a check fails, this is all that gets started elevated */
    Call->Error = ERROR_BAD_PATHNAME;
    Length = GetSystemDirectoryW(Image, MAX_PATH - 9);
    if (Length == 0 || Length >= MAX_PATH - 9)
        return 0;
    lstrcatW(Image, L"\\cmd.exe");
    wsprintfW(CommandLine, L"\"%s\" /c exit", Image);
    Request.ApplicationName = Image;
    Request.CommandLine = CommandLine;
    Request.dwShowCmd = SW_HIDE;
    Request.dwCreationFlags = CREATE_NO_WINDOW;
    Request.dwDesktopInherited = (Call->Desktop == NULL);
    Request.Desktop = (WCHAR *)Call->Desktop;

    Call->Error = ERROR_SERVICE_NOT_ACTIVE;
    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_np", NULL, (RPC_WSTR)L"\\pipe\\seclogon", NULL,
                                 &StringBinding) != RPC_S_OK)
        return 0;
    if (RpcBindingFromStringBindingW(StringBinding, &Binding) != RPC_S_OK)
    {
        RpcStringFreeW(&StringBinding);
        return 0;
    }
    RpcStringFreeW(&StringBinding);

    RpcTryExcept
    {
        SeclCreateProcessElevatedW(Binding, &Request, &Call->Response);
        Call->Error = Call->Response.dwError;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Call->Error = RpcExceptionCode();
    }
    RpcEndExcept;
    RpcBindingFree(&Binding);
    return 0;
}

static HANDLE StartBrokerCall(BROKER_CALL *Call, PCWSTR Desktop)
{
    ZeroMemory(Call, sizeof(*Call));
    Call->Desktop = Desktop;
    return CreateThread(NULL, 0, BrokerThread, Call, 0, NULL);
}

static void CloseBrokerCall(HANDLE Thread, BROKER_CALL *Call)
{
    if (Call->Response.hProcess)
        CloseHandle((HANDLE)Call->Response.hProcess);
    if (Thread)
        CloseHandle(Thread);
}

/* The prompt is a dialog of another process with a fixed caption */
static HWND FindConsent(void)
{
    HWND Window = NULL;
    DWORD ProcessId;

    while ((Window = FindWindowExW(NULL, Window, CONSENT_CLASS, CONSENT_TITLE)) != NULL)
    {
        ProcessId = 0;
        GetWindowThreadProcessId(Window, &ProcessId);
        if (ProcessId != GetCurrentProcessId() && IsWindowVisible(Window))
            return Window;
    }
    return NULL;
}

/* Waits on a handle while this thread keeps its message queue moving (the keyboard hook needs it) */
static DWORD PumpWait(HANDLE Handle, DWORD Milliseconds)
{
    DWORD Start = GetTickCount(), Elapsed, Result;
    MSG Message;

    for (;;)
    {
        while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Message);
        Elapsed = GetTickCount() - Start;
        if (Elapsed >= Milliseconds)
            return WAIT_TIMEOUT;
        Result = MsgWaitForMultipleObjects(1, &Handle, FALSE, min(Milliseconds - Elapsed, 100), QS_ALLINPUT);
        if (Result == WAIT_OBJECT_0)
            return WAIT_OBJECT_0;
    }
}

/* TRUE while the prompt is still up and the broker has not answered */
static BOOL StillAsking(HANDLE Thread)
{
    PumpWait(Thread, SETTLE_MS);
    return IsWindow(g_Consent) && IsWindowVisible(g_Consent) && WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT;
}

static LRESULT CALLBACK KeyboardProc(int Code, WPARAM wParam, LPARAM lParam)
{
    const KBDLLHOOKSTRUCT *Key = (const KBDLLHOOKSTRUCT *)lParam;

    /* Keys typed by a person into the prompt, not the ones this program injects */
    if (Code == HC_ACTION && !(Key->flags & LLKHF_INJECTED) && g_Consent && GetForegroundWindow() == g_Consent)
        InterlockedIncrement(&g_KeysSeen);
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static LRESULT CALLBACK MouseProc(int Code, WPARAM wParam, LPARAM lParam)
{
    const MSLLHOOKSTRUCT *Mouse = (const MSLLHOOKSTRUCT *)lParam;
    RECT Prompt;

    /* Pointer movement and clicks by a person over the prompt, not the ones this program injects */
    if (Code == HC_ACTION && !(Mouse->flags & LLMHF_INJECTED) && g_Consent &&
        GetWindowRect(g_Consent, &Prompt) && PtInRect(&Prompt, Mouse->pt))
        InterlockedIncrement(&g_MouseSeen);
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static LRESULT CALLBACK ThreadHookProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

/* N: a caller may be started only on its own default desktop */
static void ProbeDesktop(PCWSTR Desktop, const char *Name)
{
    BROKER_CALL Call;
    HANDLE Thread;
    HWND Prompt;

    Thread = StartBrokerCall(&Call, Desktop);
    if (!Thread)
    {
        Report(FALSE, "N %s: cannot start the broker call (error %lu)", Name, GetLastError());
        return;
    }

    if (WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0)
    {
        /* 740 sends the shell to its credentials dialog; 5 was the answer of earlier builds */
        Report((Call.Error == ERROR_ELEVATION_REQUIRED || Call.Error == ERROR_ACCESS_DENIED) &&
               Call.Response.dwProcessId == 0,
               "N %s: broker answered %lu without a prompt (expected 740 or 5), process id %lu",
               Name, Call.Error, Call.Response.dwProcessId);
    }
    else
    {
        Prompt = FindConsent();
        Report(FALSE, "N %s: the broker did not refuse at once; a prompt is %s. Answer No.",
               Name, Prompt ? "on this desktop" : "not on this desktop");
        WaitForSingleObject(Thread, ANSWER_MS);
    }
    CloseBrokerCall(Thread, &Call);
}

static void ProbeN(void)
{
    ProbeDesktop(L"WinSta0\\Winlogon", "WinSta0\\Winlogon");
    ProbeDesktop(L"WinSta0\\UacProbe", "WinSta0\\UacProbe (does not exist)");
}

/* P: nothing a limited process sends reaches the prompt */
static void ProbeP(void)
{
    BROKER_CALL Call;
    HANDLE Thread;
    HHOOK KeyHook, MouseHook, ThreadHook;
    DWORD ConsentThread, ConsentProcess = 0, Start, Error;
    WCHAR Before[128], After[128];
    RECT RectBefore, RectAfter, Button;
    INPUT Keys[4];
    HWND Yes, Cover;
    BOOL Posted, Open, Foreground, Attached;
    LRESULT Sent;
    DWORD_PTR SendResult = 0;

    Thread = StartBrokerCall(&Call, NULL);
    if (!Thread)
    {
        Report(FALSE, "P: cannot start the broker call (error %lu)", GetLastError());
        return;
    }

    Start = GetTickCount();
    while ((g_Consent = FindConsent()) == NULL && GetTickCount() - Start < APPEAR_MS &&
           WaitForSingleObject(Thread, 200) == WAIT_TIMEOUT)
    {
    }
    if (!g_Consent)
    {
        WaitForSingleObject(Thread, 1000);
        Report(FALSE, "P: no prompt appeared on this desktop (broker error so far: %lu)", Call.Error);
        if (WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT)
            Info("the broker call is still waiting; it ends when the prompt is answered or times out");
        WaitForSingleObject(Thread, ANSWER_MS);
        CloseBrokerCall(Thread, &Call);
        return;
    }
    ConsentThread = GetWindowThreadProcessId(g_Consent, &ConsentProcess);
    Info("prompt window %p, process %lu, thread %lu", (PVOID)g_Consent, ConsentProcess, ConsentThread);

    /* The keyboard hook stays for the whole check; it counts keys a person types into the prompt */
    KeyHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleW(NULL), 0);
    MouseHook = SetWindowsHookExW(WH_MOUSE_LL, MouseProc, GetModuleHandleW(NULL), 0);

    /* P1: messages */
    SetLastError(0);
    Posted = PostMessageW(g_Consent, WM_COMMAND, IDYES, 0);
    Error = GetLastError();
    Open = StillAsking(Thread);
    Report(Open, "P1 PostMessage(WM_COMMAND, IDYES): returned %d, error %lu, prompt %s",
           Posted, Error, Open ? "still open" : "gone");

    if (Open)
    {
        SetLastError(0);
        Sent = SendMessageTimeoutW(g_Consent, WM_COMMAND, IDYES, 0, SMTO_ABORTIFHUNG, 2000, &SendResult);
        Error = GetLastError();
        Open = StillAsking(Thread);
        Report(Open, "P1 SendMessage(WM_COMMAND, IDYES): returned %ld, error %lu, prompt %s",
               (long)Sent, Error, Open ? "still open" : "gone");
    }

    /* P2: synthetic input. The default button is No, so only the Yes accelerator and a click on Yes are tried */
    if (Open)
    {
        Foreground = (GetForegroundWindow() == g_Consent);
        ZeroMemory(Keys, sizeof(Keys));
        Keys[0].type = Keys[1].type = Keys[2].type = Keys[3].type = INPUT_KEYBOARD;
        Keys[0].ki.wVk = VK_MENU;
        Keys[1].ki.wVk = 'Y';
        Keys[2].ki.wVk = 'Y';
        Keys[2].ki.dwFlags = KEYEVENTF_KEYUP;
        Keys[3].ki.wVk = VK_MENU;
        Keys[3].ki.dwFlags = KEYEVENTF_KEYUP;
        SetLastError(0);
        Sent = SendInput(4, Keys, sizeof(INPUT));
        Error = GetLastError();
        Open = StillAsking(Thread);
        Report(Open, "P2 SendInput(Alt+Y): %ld of 4 events taken, error %lu, prompt was %sthe foreground window, prompt %s",
               (long)Sent, Error, Foreground ? "" : "NOT ", Open ? "still open" : "gone");
    }

    if (Open)
    {
        Yes = GetDlgItem(g_Consent, IDYES);
        if (Yes && GetWindowRect(Yes, &Button))
        {
            SetCursorPos((Button.left + Button.right) / 2, (Button.top + Button.bottom) / 2);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            Open = StillAsking(Thread);
            Report(Open, "P2 synthetic click on the Yes button: prompt %s", Open ? "still open" : "gone");
        }
        else
        {
            Info("P2 click: the Yes button could not be located (error %lu); not tried", GetLastError());
        }
    }

    /* P3: a hook on the prompt's thread */
    if (Open)
    {
        SetLastError(0);
        ThreadHook = SetWindowsHookExW(WH_GETMESSAGE, ThreadHookProc, GetModuleHandleW(NULL), ConsentThread);
        Error = GetLastError();
        Report(ThreadHook == NULL, "P3 SetWindowsHookEx(WH_GETMESSAGE) on the prompt's thread: %s, error %lu",
               ThreadHook ? "INSTALLED" : "refused", Error);
        if (ThreadHook)
            UnhookWindowsHookEx(ThreadHook);
    }

    /* P7: sharing the prompt thread's input state */
    if (Open)
    {
        SetLastError(0);
        Attached = AttachThreadInput(GetCurrentThreadId(), ConsentThread, TRUE);
        Error = GetLastError();
        Report(!Attached, "P7 AttachThreadInput to the prompt's thread: %s, error %lu",
               Attached ? "ATTACHED" : "refused", Error);
        if (Attached)
            AttachThreadInput(GetCurrentThreadId(), ConsentThread, FALSE);
    }

    /* P8: a click queued to a window of this process that covers the Yes button; the window goes away
     * before the click is read, so the click would be handed to the window below it */
    if (Open && (Yes = GetDlgItem(g_Consent, IDYES)) != NULL && GetWindowRect(Yes, &Button))
    {
        Cover = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"STATIC", L"", WS_POPUP | WS_VISIBLE | SS_NOTIFY,
                                Button.left, Button.top, Button.right - Button.left, Button.bottom - Button.top,
                                NULL, NULL, GetModuleHandleW(NULL), NULL);
        if (Cover)
        {
            Foreground = SetForegroundWindow(Cover) && GetForegroundWindow() == Cover;
            SetCursorPos((Button.left + Button.right) / 2, (Button.top + Button.bottom) / 2);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            DestroyWindow(Cover);
            Open = StillAsking(Thread);
            Report(Open, "P8 click queued to a covering window, then the window removed: cover was %sthe foreground window, prompt %s",
                   Foreground ? "" : "NOT ", Open ? "still open" : "gone");
        }
        else
        {
            Info("P8 the covering window could not be created (error %lu); not tried", GetLastError());
        }
    }

    /* P9: a window owned by the prompt, and a child window inside it. Either would share the prompt's
     * input state, and the child could cover the prompt's text. Neither is shown; both are removed at once. */
    if (Open)
    {
        SetLastError(0);
        Cover = CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 8, 8, g_Consent, NULL, GetModuleHandleW(NULL), NULL);
        Error = GetLastError();
        Report(Cover == NULL, "P9 CreateWindowEx with the prompt as owner: %s, error %lu", Cover ? "CREATED" : "refused", Error);
        if (Cover)
            DestroyWindow(Cover);

        SetLastError(0);
        Cover = CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 0, 0, 8, 8, g_Consent, NULL, GetModuleHandleW(NULL), NULL);
        Error = GetLastError();
        Report(Cover == NULL, "P9 CreateWindowEx with the prompt as parent: %s, error %lu", Cover ? "CREATED" : "refused", Error);
        if (Cover)
            DestroyWindow(Cover);
        Open = StillAsking(Thread);
    }

    /* P4: window calls: hide, disable, move, rename */
    if (Open)
    {
        Before[0] = After[0] = 0;
        GetWindowTextW(g_Consent, Before, _countof(Before));
        GetWindowRect(g_Consent, &RectBefore);

        ShowWindow(g_Consent, SW_HIDE);
        Report(IsWindowVisible(g_Consent), "P4 ShowWindow(SW_HIDE): prompt is %s",
               IsWindowVisible(g_Consent) ? "still visible" : "HIDDEN");
        ShowWindow(g_Consent, SW_SHOW);

        EnableWindow(g_Consent, FALSE);
        Report(IsWindowEnabled(g_Consent), "P4 EnableWindow(FALSE): prompt is %s",
               IsWindowEnabled(g_Consent) ? "still enabled" : "DISABLED");
        EnableWindow(g_Consent, TRUE);

        SetWindowPos(g_Consent, HWND_BOTTOM, RectBefore.left + 60, RectBefore.top + 60, 0, 0,
                     SWP_NOSIZE | SWP_NOACTIVATE);
        GetWindowRect(g_Consent, &RectAfter);
        Report(EqualRect(&RectBefore, &RectAfter), "P4 SetWindowPos: prompt %s",
               EqualRect(&RectBefore, &RectAfter) ? "did not move" : "MOVED");

        SetWindowTextW(g_Consent, L"uacprobe");
        PumpWait(Thread, 300);
        GetWindowTextW(g_Consent, After, _countof(After));
        Report(lstrcmpW(Before, After) == 0, "P4 SetWindowText: caption %s",
               lstrcmpW(Before, After) == 0 ? "unchanged" : "CHANGED");

        Open = StillAsking(Thread);
    }

    /* The end: only a person answers. No elevated process may exist unless a person said Yes. */
    if (WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT)
    {
        printf("ACTION: move the pointer once across the prompt, then answer it with No with the keyboard (Enter). Waiting up to %u seconds.\n",
               ANSWER_MS / 1000);
        fflush(stdout);
        PumpWait(Thread, ANSWER_MS);
    }
    if (WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT)
    {
        Report(FALSE, "P5 the broker call did not end");
    }
    else
    {
        Report(Call.Error != ERROR_SUCCESS && Call.Response.dwProcessId == 0,
               "P5 end of the request: broker answered %lu (1223 = cancelled), process id %lu",
               Call.Error, Call.Response.dwProcessId);
    }

    if (KeyHook)
    {
        Report(g_KeysSeen == 0, "P6 low-level keyboard hook: %ld keys typed into the prompt were seen%s",
               g_KeysSeen, g_KeysSeen == 0 ? " (only meaningful if No was given with the keyboard)" : "");
        UnhookWindowsHookEx(KeyHook);
    }
    else
    {
        Info("P6 the low-level keyboard hook could not be installed; not checked");
    }
    if (MouseHook)
    {
        Report(g_MouseSeen == 0, "P6 low-level mouse hook: %ld pointer events over the prompt were seen%s",
               g_MouseSeen, g_MouseSeen == 0 ? " (only meaningful if the pointer was moved over the prompt)" : "");
        UnhookWindowsHookEx(MouseHook);
    }
    else
    {
        Info("P6 the low-level mouse hook could not be installed; not checked");
    }

    g_Consent = NULL;
    if (WaitForSingleObject(Thread, 0) == WAIT_OBJECT_0)
        CloseBrokerCall(Thread, &Call);
}

/* P10: what the limited side can do to an elevated process of the same user, and to its token */
static DWORD QueryTokenDword(HANDLE Token, int Class)
{
    DWORD Value = 0xFFFFFFFF, Length;

    if (!GetTokenInformation(Token, Class, &Value, sizeof(Value), &Length))
        Value = 0xFFFFFFFF;
    return Value;
}

static DWORD OpenSystemKeyForWrite(void)
{
    HKEY Key;
    DWORD Error;

    /* Only the access is asked for; nothing is written */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &Key);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
    return Error;
}

/* The second impersonation rule rests on the limited mark staying on every copy of a limited token */
static void ProbeOwnCopies(void)
{
    static const struct { DWORD Flags; const char *Name; } Filters[] =
    {
        { 0, "no change asked" },
        { DISABLE_MAX_PRIVILEGE, "privileges removed" },
    };
    HANDLE Own, Copy;
    DWORD Type;
    UINT i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Own))
    {
        Info("P10 own token could not be opened for copies, error %lu; not checked", GetLastError());
        return;
    }
    if (DuplicateTokenEx(Own, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Copy))
    {
        Type = QueryTokenDword(Copy, TokenElevationType);
        Report(Type == TokenElevationTypeLimited, "P10 copy of the limited token: elevation type %lu (3 = limited)", Type);
        CloseHandle(Copy);
    }
    else
    {
        Info("P10 DuplicateTokenEx on the own token failed, error %lu; not checked", GetLastError());
    }
    for (i = 0; i < _countof(Filters); i++)
    {
        if (CreateRestrictedToken(Own, Filters[i].Flags, 0, NULL, 0, NULL, 0, NULL, &Copy))
        {
            Type = QueryTokenDword(Copy, TokenElevationType);
            Report(Type == TokenElevationTypeLimited,
                   "P10 filtered copy of the limited token (%s): elevation type %lu (3 = limited)", Filters[i].Name, Type);
            CloseHandle(Copy);
        }
        else
        {
            Info("P10 CreateRestrictedToken (%s) failed, error %lu; not checked", Filters[i].Name, GetLastError());
        }
    }
    CloseHandle(Own);
}

static void ProbeT(DWORD ProcessId)
{
    static const struct { DWORD Access; const char *Name; } Rights[] =
    {
        { PROCESS_VM_WRITE, "PROCESS_VM_WRITE" },
        { PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION" },
        { PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD" },
        { PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE" },
        { PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION" },
        { PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME" },
        { PROCESS_VM_READ, "PROCESS_VM_READ" },
        { PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" },
    };
    SID_IDENTIFIER_AUTHORITY LabelAuthority = { { 0, 0, 0, 0, 0, 16 } };
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Process, Token = NULL, Copy = NULL, ThreadToken;
    PSID Medium = NULL;
    DWORD Error, Before, After, Level, Type;
    UINT i;

    ProbeOwnCopies();

    for (i = 0; i < _countof(Rights); i++)
    {
        Process = OpenProcess(Rights[i].Access, FALSE, ProcessId);
        Error = Process ? ERROR_SUCCESS : GetLastError();
        Report(Process == NULL && Error == ERROR_ACCESS_DENIED, "P10 OpenProcess(%s) on process %lu: %s, error %lu",
               Rights[i].Name, ProcessId, Process ? "GRANTED" : "refused", Error);
        if (Process)
            CloseHandle(Process);
    }

    /* Reported only: the reference system has to be measured on this right first. The process is not ended. */
    Process = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);
    Error = Process ? ERROR_SUCCESS : GetLastError();
    Info("P10 OpenProcess(PROCESS_TERMINATE): %s, error %lu (the right is not used)", Process ? "granted" : "refused", Error);
    if (Process)
        CloseHandle(Process);

    /* The chain: limited query right, token, copy, lower integrity, impersonate, use */
    Before = OpenSystemKeyForWrite();
    if (Before == ERROR_SUCCESS)
        Info("P10 this process can already open HKLM\\SYSTEM for writing; the registry step says nothing here");

    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!Process)
    {
        Error = GetLastError();
        if (Error == ERROR_INVALID_PARAMETER)
            Report(FALSE, "P10 chain: process %lu does not exist; give the id of a running elevated process", ProcessId);
        else
            Report(TRUE, "P10 chain stopped at step 1: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) error %lu", Error);
        return;
    }
    Info("P10 chain step 1: limited query right on the process granted");

    if (!OpenProcessToken(Process, TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
    {
        Report(TRUE, "P10 chain stopped at step 2: OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY) error %lu", GetLastError());
        goto Done;
    }
    Type = QueryTokenDword(Token, TokenElevationType);
    Info("P10 chain step 2: token opened; elevation type %lu (2 = full), elevated %lu", Type,
         QueryTokenDword(Token, TokenElevation));
    if (Type == TokenElevationTypeLimited)
    {
        Report(FALSE, "P10 chain: process %lu is not elevated; give the id of an elevated process of this user", ProcessId);
        goto Done;
    }

    if (!DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Copy))
    {
        Report(TRUE, "P10 chain stopped at step 3: DuplicateTokenEx error %lu", GetLastError());
        goto Done;
    }
    Info("P10 chain step 3: impersonation copy with full access granted");

    if (!AllocateAndInitializeSid(&LabelAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &Medium))
    {
        Info("P10 chain: the label could not be built, error %lu; not checked further", GetLastError());
        goto Done;
    }
    Label.Label.Sid = Medium;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    if (!SetTokenInformation(Copy, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(Medium)))
        Info("P10 chain step 4: lowering the integrity of the copy failed, error %lu; going on", GetLastError());
    else
        Info("P10 chain step 4: integrity of the copy lowered to medium");

    if (!SetThreadToken(NULL, Copy))
    {
        Report(TRUE, "P10 chain stopped at step 5: SetThreadToken error %lu", GetLastError());
        goto Done;
    }
    Level = 0xFFFFFFFF;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &ThreadToken))
    {
        Level = QueryTokenDword(ThreadToken, TokenImpersonationLevel);
        CloseHandle(ThreadToken);
    }
    After = OpenSystemKeyForWrite();
    RevertToSelf();
    /* Identification at most is the wanted result; the registry step shows what a higher level is worth */
    Report(Level <= (DWORD)SecurityIdentification && (After != ERROR_SUCCESS || Before == ERROR_SUCCESS),
           "P10 chain step 5: thread token level %lu (1 = identification, 2 = impersonation); "
           "HKLM\\SYSTEM for writing: before %lu, with the copy %lu (5 = refused)", Level, Before, After);

Done:
    if (Medium)
        FreeSid(Medium);
    if (Copy)
        CloseHandle(Copy);
    if (Token)
        CloseHandle(Token);
    CloseHandle(Process);
}

int wmain(int argc, WCHAR *argv[])
{
    BOOL DoN = TRUE, DoP = TRUE, DoT = FALSE;

    if (argc > 1)
    {
        DoN = (argv[1][0] == L'n' || argv[1][0] == L'N');
        DoP = (argv[1][0] == L'p' || argv[1][0] == L'P');
        DoT = ((argv[1][0] == L't' || argv[1][0] == L'T') && argc > 2);
        if (!DoN && !DoP && !DoT)
        {
            printf("usage: uacprobe [n|p|t <id of an elevated process of this user>]\n");
            return 100;
        }
    }

    if (!IsLimitedCaller())
    {
        printf("SKIP: this process is not the limited side of a split administrator logon "
               "(EnableLUA=1 and a limited administrator are needed)\n");
        return 100;
    }

    if (DoN)
        ProbeN();
    if (DoP)
        ProbeP();
    if (DoT)
        ProbeT(wcstoul(argv[2], NULL, 10));

    printf("DONE: %d FAIL\n", g_Failures);
    return g_Failures;
}

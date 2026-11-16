/*
 * PROJECT:     LiberNT Consent UI
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Asks the user whether an administrative program may run
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 *
 * Started by the secondary logon service as SYSTEM in the user's session, on the
 * user's desktop or on the secure desktop. Command line:
 *   consent.exe <caller hwnd in hex> "<account>" "<final path>" <command line>
 *   consent.exe <caller hwnd in hex> "<account>" "<final path>" /cred:<record>,<verdict> <command line>
 * The second form asks for a user name and a password and hands them to the service
 * over the two inherited pipes (consentproto.h); the service does the logon and answers.
 * The exit code is IDYES or IDNO.
 */

#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <wchar.h>
#include <stdlib.h>
#include <strsafe.h>
#include <consentproto.h>
#include "resource.h"

/* Longer command lines are cut for display; the length is shown so a cut is visible */
#define CONSENT_MAX_COMMAND 160

#ifndef OIC_SHIELD
#define OIC_SHIELD 32518
#endif

typedef struct _CONSENT_ARGS
{
    HWND hwndCaller;
    PCWSTR Account;
    PCWSTR ImagePath;
    PCWSTR CommandLine;
    HANDLE hRecord;         /* credentials mode: write end of the record pipe */
    HANDLE hVerdict;        /* credentials mode: read end of the verdict pipe */
} CONSENT_ARGS, *PCONSENT_ARGS;

/* One line, single blanks, no control characters, cut with its length when long */
static
void
FormatCommandLine(PCWSTR CommandLine, PWSTR Display, size_t DisplayChars)
{
    size_t Length = 0, Total = wcslen(CommandLine), Pos;
    BOOL Blank = TRUE;

    for (Pos = 0; Pos < Total && Length + 1 < DisplayChars; Pos++)
    {
        WCHAR c = CommandLine[Pos];

        if (c <= L' ' || c == 0x7F)
        {
            if (!Blank)
                Display[Length++] = L' ';
            Blank = TRUE;
            continue;
        }
        Display[Length++] = c;
        Blank = FALSE;
        if (Length >= CONSENT_MAX_COMMAND)
            break;
    }
    while (Length > 0 && Display[Length - 1] == L' ')
        Length--;
    Display[Length] = UNICODE_NULL;
    if (Pos < Total)
    {
        StringCchCatW(Display, DisplayChars, L"\x2026");
        StringCchPrintfW(Display + wcslen(Display), DisplayChars - wcslen(Display),
                         L" (%Iu characters)", Total);
    }
}

/* The caller's window only says where the prompt goes; it never owns the prompt */
static
void
PlaceNearCaller(HWND hwnd, HWND hwndCaller)
{
    RECT Caller, Self, Work;
    int x, y;

    if (hwndCaller == NULL || !IsWindow(hwndCaller) || !GetWindowRect(hwndCaller, &Caller) ||
        !GetWindowRect(hwnd, &Self) || !SystemParametersInfoW(SPI_GETWORKAREA, 0, &Work, 0))
    {
        return;
    }
    x = (Caller.left + Caller.right - (Self.right - Self.left)) / 2;
    y = (Caller.top + Caller.bottom - (Self.bottom - Self.top)) / 2;
    x = max(Work.left, min(x, Work.right - (Self.right - Self.left)));
    y = max(Work.top, min(y, Work.bottom - (Self.bottom - Self.top)));
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static
void
FillCommonFields(HWND hwnd, PCONSENT_ARGS Args)
{
    HICON hIcon = LoadImageW(NULL, MAKEINTRESOURCEW(OIC_SHIELD), IMAGE_ICON, 32, 32, LR_SHARED);
    WCHAR Display[CONSENT_MAX_COMMAND + 48];

    if (hIcon)
        SendDlgItemMessageW(hwnd, IDC_SHIELD, STM_SETICON, (WPARAM)hIcon, 0);
    SetDlgItemTextW(hwnd, IDC_IMAGE, Args->ImagePath);
    FormatCommandLine(Args->CommandLine, Display, _countof(Display));
    SetDlgItemTextW(hwnd, IDC_COMMAND, Display);
    PlaceNearCaller(hwnd, Args->hwndCaller);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(hwnd);
}

static
INT_PTR
CALLBACK
ConsentDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            PCONSENT_ARGS Args = (PCONSENT_ARGS)lParam;
            SetDlgItemTextW(hwnd, IDC_ACCOUNT, Args->Account);
            FillCommonFields(hwnd, Args);
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDYES || LOWORD(wParam) == IDNO || LOWORD(wParam) == IDCANCEL)
            {
                EndDialog(hwnd, LOWORD(wParam) == IDYES ? IDYES : IDNO);
                return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(hwnd, IDNO);
            return TRUE;
    }
    return FALSE;
}

/* Writes exactly one record; the buffer is wiped by the caller */
static
BOOL
SendRecord(HANDLE hRecord, PCONSENT_CREDENTIAL_RECORD Record)
{
    DWORD Written = 0;
    return WriteFile(hRecord, Record, sizeof(*Record), &Written, NULL) && Written == sizeof(*Record);
}

/* Reads exactly one verdict; anything else counts as a refusal */
static
CONSENT_VERDICT
ReadVerdict(HANDLE hVerdict)
{
    ULONG Verdict = ConsentVerdictRefused;
    DWORD Read = 0;

    if (!ReadFile(hVerdict, &Verdict, sizeof(Verdict), &Read, NULL) || Read != sizeof(Verdict))
        return ConsentVerdictRefused;
    if (Verdict < ConsentVerdictOk || Verdict > ConsentVerdictRefused)
        return ConsentVerdictRefused;
    return (CONSENT_VERDICT)Verdict;
}

/* DOMAIN\user and user@domain are split; anything else is the user name alone */
static
void
SplitAccount(PCWSTR Typed, PCONSENT_CREDENTIAL_RECORD Record)
{
    PCWSTR Sep = wcschr(Typed, L'\\');
    size_t Length;

    if (Sep != NULL)
    {
        Length = min((size_t)(Sep - Typed), CONSENT_MAX_DOMAIN - 1);
        wcsncpy(Record->Domain, Typed, Length);
        Record->Domain[Length] = UNICODE_NULL;
        StringCchCopyW(Record->User, CONSENT_MAX_USER, Sep + 1);
    }
    else
    {
        StringCchCopyW(Record->User, CONSENT_MAX_USER, Typed);
        Sep = wcschr(Record->User, L'@');
        if (Sep != NULL)
        {
            StringCchCopyW(Record->Domain, CONSENT_MAX_DOMAIN, Sep + 1);
            Record->User[Sep - Record->User] = UNICODE_NULL;
        }
    }
    Record->UserLength = (ULONG)wcslen(Record->User);
    Record->DomainLength = (ULONG)wcslen(Record->Domain);
}

static
INT_PTR
CALLBACK
CredentialsDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static PCONSENT_ARGS Args;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            Args = (PCONSENT_ARGS)lParam;
            SendDlgItemMessageW(hwnd, IDC_USER, EM_LIMITTEXT, CONSENT_MAX_USER - 1, 0);
            SendDlgItemMessageW(hwnd, IDC_PASSWORD, EM_LIMITTEXT, CONSENT_MAX_PASSWORD - 1, 0);
            if (Args->Account[0] != UNICODE_NULL)
                SetDlgItemTextW(hwnd, IDC_USER, Args->Account);
            FillCommonFields(hwnd, Args);
            SetFocus(GetDlgItem(hwnd, Args->Account[0] != UNICODE_NULL ? IDC_PASSWORD : IDC_USER));
            return FALSE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDYES || LOWORD(wParam) == IDOK)
            {
                CONSENT_CREDENTIAL_RECORD Record;
                WCHAR Typed[CONSENT_MAX_USER + CONSENT_MAX_DOMAIN];
                CONSENT_VERDICT Verdict;
                BOOL Sent;

                ZeroMemory(&Record, sizeof(Record));
                Record.Magic = CONSENT_RECORD_MAGIC;
                Record.Answer = IDYES;
                GetDlgItemTextW(hwnd, IDC_USER, Typed, _countof(Typed));
                SplitAccount(Typed, &Record);
                GetDlgItemTextW(hwnd, IDC_PASSWORD, Record.Password, CONSENT_MAX_PASSWORD);
                Record.PasswordLength = (ULONG)wcslen(Record.Password);

                /* The service decides; this process only shows the reason and asks again */
                Sent = SendRecord(Args->hRecord, &Record);
                SecureZeroMemory(&Record, sizeof(Record));
                SetDlgItemTextW(hwnd, IDC_PASSWORD, L"");
                if (!Sent)
                {
                    EndDialog(hwnd, IDNO);
                    return TRUE;
                }
                Verdict = ReadVerdict(Args->hVerdict);
                switch (Verdict)
                {
                    case ConsentVerdictOk:
                        EndDialog(hwnd, IDYES);
                        break;
                    case ConsentVerdictWrongPassword:
                        SetDlgItemTextW(hwnd, IDC_STATUS, L"The user name or password is incorrect.");
                        SetFocus(GetDlgItem(hwnd, IDC_PASSWORD));
                        break;
                    case ConsentVerdictCannotApprove:
                        SetDlgItemTextW(hwnd, IDC_STATUS, L"This account cannot approve the request.");
                        SetFocus(GetDlgItem(hwnd, IDC_USER));
                        break;
                    default:
                        EndDialog(hwnd, IDNO);
                        break;
                }
                return TRUE;
            }
            if (LOWORD(wParam) == IDNO || LOWORD(wParam) == IDCANCEL)
            {
                CONSENT_CREDENTIAL_RECORD Record;

                /* Tells the waiting service that the user declined */
                ZeroMemory(&Record, sizeof(Record));
                Record.Magic = CONSENT_RECORD_MAGIC;
                Record.Answer = IDNO;
                SendRecord(Args->hRecord, &Record);
                SetDlgItemTextW(hwnd, IDC_PASSWORD, L"");
                EndDialog(hwnd, IDNO);
                return TRUE;
            }
            break;

        case WM_CLOSE:
            SendMessageW(hwnd, WM_COMMAND, IDNO, 0);
            return TRUE;
    }
    return FALSE;
}

/* Skips one argument (quoted or bare) and the blanks after it */
static
PWSTR
SkipArgument(PWSTR p)
{
    if (*p == L'"')
    {
        p++;
        while (*p && *p != L'"')
            p++;
        if (*p == L'"')
            p++;
    }
    else
    {
        while (*p && *p != L' ' && *p != L'\t')
            p++;
    }
    while (*p == L' ' || *p == L'\t')
        p++;
    return p;
}

int
WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    CONSENT_ARGS Args = { NULL, L"", L"", L"", NULL, NULL };
    PWSTR p = GetCommandLineW(), q;
    INT_PTR Answer;

    /* consent.exe <caller hwnd> "<account>" "<path>" [/cred:<record>,<verdict>] <command line> */
    p = SkipArgument(p);
    if (*p == UNICODE_NULL)
        return IDNO;
    Args.hwndCaller = (HWND)(ULONG_PTR)wcstoull(p, &q, 16);
    p = SkipArgument(p);
    if (*p != L'"')
        return IDNO;
    Args.Account = p + 1;
    q = wcschr(p + 1, L'"');
    if (q == NULL)
        return IDNO;
    *q = UNICODE_NULL;
    p = SkipArgument(q + 1);
    if (*p != L'"')
        return IDNO;
    Args.ImagePath = p + 1;
    q = wcschr(p + 1, L'"');
    if (q == NULL)
        return IDNO;
    *q = UNICODE_NULL;
    p = q + 1;
    while (*p == L' ' || *p == L'\t')
        p++;
    if (_wcsnicmp(p, L"/cred:", 6) == 0)
    {
        Args.hRecord = (HANDLE)(ULONG_PTR)wcstoull(p + 6, &q, 10);
        if (*q != L',')
            return IDNO;
        Args.hVerdict = (HANDLE)(ULONG_PTR)wcstoull(q + 1, &q, 10);
        if (Args.hRecord == NULL || Args.hVerdict == NULL || (*q != L' ' && *q != L'\t' && *q != UNICODE_NULL))
            return IDNO;
        p = q;
        while (*p == L' ' || *p == L'\t')
            p++;
    }
    Args.CommandLine = p;

    if (Args.hwndCaller != NULL && !IsWindow(Args.hwndCaller))
        Args.hwndCaller = NULL;

    /* No owner: an owned dialog can be reached through its owner's thread, this one cannot */
    if (Args.hRecord != NULL)
    {
        Answer = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_CONSENT_CREDENTIALS), NULL, CredentialsDlgProc, (LPARAM)&Args);
        CloseHandle(Args.hRecord);
        CloseHandle(Args.hVerdict);
    }
    else
    {
        Answer = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_CONSENT), NULL, ConsentDlgProc, (LPARAM)&Args);
    }
    return (Answer == IDYES) ? IDYES : IDNO;
}

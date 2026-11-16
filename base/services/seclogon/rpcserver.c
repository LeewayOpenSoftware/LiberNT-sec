/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Secondary Logon service RPC server
 * COPYRIGHT:   Eric Kohl 2022 <eric.kohl@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

#include <seclogon_s.h>
#include <wlsecdesk_c.h>
#include <consentproto.h>

WINE_DEFAULT_DEBUG_CHANNEL(seclogon);

static BOOL IsUserElevationDenied(VOID);

/* GLOBALS *******************************************************************/

CRITICAL_SECTION DesktopAccessLock;

/* FUNCTIONS *****************************************************************/

static
PSID
GetLogonSid(
    _In_ HANDLE hToken,
    _Out_ PVOID *Buffer)
{
    PTOKEN_GROUPS Groups;
    PTOKEN_USER User;
    DWORD Length = 0, i;

    *Buffer = NULL;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Length);
    if (Length && (Groups = HeapAlloc(GetProcessHeap(), 0, Length)) != NULL)
    {
        if (GetTokenInformation(hToken, TokenGroups, Groups, Length, &Length))
        {
            for (i = 0; i < Groups->GroupCount; i++)
            {
                if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    *Buffer = Groups;
                    return Groups->Groups[i].Sid;
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, Groups);
    }

    Length = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &Length);
    if (Length && (User = HeapAlloc(GetProcessHeap(), 0, Length)) != NULL)
    {
        if (GetTokenInformation(hToken, TokenUser, User, Length, &Length))
        {
            *Buffer = User;
            return User->User.Sid;
        }
        HeapFree(GetProcessHeap(), 0, User);
    }
    return NULL;
}

typedef struct _DESKTOP_GRANT
{
    LIST_ENTRY ListEntry;
    LONG Count;
    BOOL WinStaAdded;
    BOOL DesktopAdded;
    PSID Sid;
    WCHAR Path[MAX_PATH];
} DESKTOP_GRANT, *PDESKTOP_GRANT;

typedef struct _DESKTOP_GRANT_WAIT
{
    PDESKTOP_GRANT Grant;
    HANDLE hProcess;
    HANDLE hWait;
    LONG Owners;
} DESKTOP_GRANT_WAIT, *PDESKTOP_GRANT_WAIT;

static LIST_ENTRY DesktopGrantList = { &DesktopGrantList, &DesktopGrantList };

static
BOOL
FindAllowAce(
    _In_opt_ PACL Dacl,
    _In_ PSID Sid,
    _Out_opt_ PDWORD Index)
{
    ACL_SIZE_INFORMATION Information;
    PACCESS_ALLOWED_ACE Ace;
    DWORD i;

    if (Dacl == NULL ||
        !GetAclInformation(Dacl, &Information, sizeof(Information), AclSizeInformation))
    {
        return FALSE;
    }
    for (i = 0; i < Information.AceCount; i++)
    {
        if (GetAce(Dacl, i, (PVOID *)&Ace) &&
            Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            EqualSid((PSID)&Ace->SidStart, Sid))
        {
            if (Index)
                *Index = i;
            return TRUE;
        }
    }
    return FALSE;
}

static
DWORD
AllowSid(
    _In_ HANDLE hObject,
    _In_ PSID Sid,
    _In_ ACCESS_MASK Access,
    _Out_ PBOOL Added)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PACL OldDacl = NULL, NewDacl = NULL;
    EXPLICIT_ACCESSW Entry;
    DWORD dwError;

    *Added = FALSE;
    dwError = GetSecurityInfo(hObject, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                              NULL, NULL, &OldDacl, NULL, &SecurityDescriptor);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (FindAllowAce(OldDacl, Sid, NULL))
    {
        LocalFree(SecurityDescriptor);
        return ERROR_SUCCESS;
    }

    ZeroMemory(&Entry, sizeof(Entry));
    Entry.grfAccessPermissions = Access;
    Entry.grfAccessMode = GRANT_ACCESS;
    Entry.grfInheritance = NO_INHERITANCE;
    Entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    Entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    Entry.Trustee.ptstrName = (LPWSTR)Sid;

    dwError = SetEntriesInAclW(1, &Entry, OldDacl, &NewDacl);
    if (dwError == ERROR_SUCCESS)
    {
        dwError = SetSecurityInfo(hObject, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, NewDacl, NULL);
        *Added = (dwError == ERROR_SUCCESS);
        LocalFree(NewDacl);
    }
    LocalFree(SecurityDescriptor);
    return dwError;
}

static
VOID
RevokeSid(
    _In_ HANDLE hObject,
    _In_ PSID Sid)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PACL Dacl = NULL;
    DWORD Index;

    if (GetSecurityInfo(hObject, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &Dacl, NULL, &SecurityDescriptor) != ERROR_SUCCESS)
    {
        return;
    }
    if (FindAllowAce(Dacl, Sid, &Index) && DeleteAce(Dacl, Index))
        SetSecurityInfo(hObject, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL);
    LocalFree(SecurityDescriptor);
}

#define GRANT_WINSTA_ACCESS (WINSTA_ALL_ACCESS | STANDARD_RIGHTS_REQUIRED)
#define GRANT_DESKTOP_ACCESS (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | \
                              DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
                              DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP | \
                              STANDARD_RIGHTS_REQUIRED)

static
BOOL
IsServiceAccountToken(
    _In_ HANDLE hToken)
{
    BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    DWORD Length;

    if (!GetTokenInformation(hToken, TokenUser, User, sizeof(Buffer), &Length))
        return TRUE;
    return IsWellKnownSid(User->User.Sid, WinNetworkServiceSid) ||
           IsWellKnownSid(User->User.Sid, WinLocalServiceSid);
}

/* Caller holds DesktopAccessLock: the desktop is opened through the process window station */
static
DWORD
OpenDesktopPath(
    _In_ PCWSTR DesktopPath,
    _In_ ACCESS_MASK WinStaAccess,
    _In_ ACCESS_MASK DesktopAccess,
    _Out_ HWINSTA *phWinSta,
    _Out_ HDESK *phDesktop)
{
    WCHAR WinStaName[MAX_PATH];
    PCWSTR DesktopName, Separator;
    HWINSTA hOldWinSta;
    DWORD dwError;

    *phWinSta = NULL;
    *phDesktop = NULL;
    Separator = wcschr(DesktopPath, L'\\');
    if (Separator)
    {
        if ((SIZE_T)(Separator - DesktopPath) >= ARRAYSIZE(WinStaName))
            return ERROR_INVALID_PARAMETER;
        CopyMemory(WinStaName, DesktopPath, (Separator - DesktopPath) * sizeof(WCHAR));
        WinStaName[Separator - DesktopPath] = UNICODE_NULL;
        DesktopName = Separator + 1;
    }
    else
    {
        wcscpy(WinStaName, L"WinSta0");
        DesktopName = DesktopPath;
    }

    *phWinSta = OpenWindowStationW(WinStaName, FALSE, WinStaAccess);
    if (*phWinSta == NULL)
        return GetLastError();

    hOldWinSta = GetProcessWindowStation();
    if (!SetProcessWindowStation(*phWinSta))
        return GetLastError();
    *phDesktop = OpenDesktopW(DesktopName, 0, FALSE, DesktopAccess);
    dwError = *phDesktop ? ERROR_SUCCESS : GetLastError();
    SetProcessWindowStation(hOldWinSta);
    return dwError;
}

static
VOID
CloseDesktopPath(
    _In_opt_ HWINSTA hWinSta,
    _In_opt_ HDESK hDesktop)
{
    if (hDesktop)
        CloseDesktop(hDesktop);
    if (hWinSta)
        CloseWindowStation(hWinSta);
}

/* Caller holds DesktopAccessLock: what is granted must be what the client may already use itself */
static
DWORD
CheckClientDesktopAccess(
    _In_ handle_t hBinding,
    _In_ PCWSTR DesktopPath)
{
    HANDLE hClientToken = NULL;
    HWINSTA hWinSta = NULL;
    HDESK hDesktop = NULL;
    DWORD dwError;

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
        return ERROR_ACCESS_DENIED;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hClientToken))
        dwError = GetLastError();
    else if (IsServiceAccountToken(hClientToken))
        dwError = ERROR_ACCESS_DENIED;
    else
        dwError = OpenDesktopPath(DesktopPath, GRANT_WINSTA_ACCESS, GRANT_DESKTOP_ACCESS, &hWinSta, &hDesktop);

    RpcRevertToSelf();

    CloseDesktopPath(hWinSta, hDesktop);
    if (hClientToken != NULL)
        CloseHandle(hClientToken);
    return dwError;
}

/* Windows grants the new logon access to the window station and desktop it inherits */
static
PDESKTOP_GRANT
GrantDesktopAccess(
    _In_ handle_t hBinding,
    _In_ HANDLE hToken,
    _In_ PCWSTR DesktopPath,
    _Out_ PDWORD pdwError)
{
    PDESKTOP_GRANT Grant = NULL;
    PLIST_ENTRY Entry;
    HWINSTA hWinSta;
    HDESK hDesktop;
    PVOID SidBuffer;
    PSID Sid;
    DWORD dwError, SidLength;

    if (wcslen(DesktopPath) >= MAX_PATH)
    {
        *pdwError = ERROR_INVALID_PARAMETER;
        return NULL;
    }
    if (IsServiceAccountToken(hToken))
    {
        *pdwError = ERROR_ACCESS_DENIED;
        return NULL;
    }
    Sid = GetLogonSid(hToken, &SidBuffer);
    if (Sid == NULL)
    {
        *pdwError = GetLastError();
        return NULL;
    }

    EnterCriticalSection(&DesktopAccessLock);
    dwError = CheckClientDesktopAccess(hBinding, DesktopPath);
    if (dwError != ERROR_SUCCESS)
    {
        Grant = NULL;
        goto done;
    }

    for (Entry = DesktopGrantList.Flink; Entry != &DesktopGrantList; Entry = Entry->Flink)
    {
        Grant = CONTAINING_RECORD(Entry, DESKTOP_GRANT, ListEntry);
        if (EqualSid(Grant->Sid, Sid) && !_wcsicmp(Grant->Path, DesktopPath))
        {
            Grant->Count++;
            dwError = ERROR_SUCCESS;
            goto done;
        }
    }

    SidLength = GetLengthSid(Sid);
    Grant = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Grant) + SidLength);
    if (Grant == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    Grant->Count = 1;
    Grant->Sid = (PSID)(Grant + 1);
    CopySid(SidLength, Grant->Sid, Sid);
    wcscpy(Grant->Path, DesktopPath);

    dwError = OpenDesktopPath(DesktopPath, READ_CONTROL | WRITE_DAC | WINSTA_ENUMDESKTOPS, READ_CONTROL | WRITE_DAC,
                              &hWinSta, &hDesktop);
    if (dwError == ERROR_SUCCESS)
        dwError = AllowSid(hWinSta, Sid, GRANT_WINSTA_ACCESS, &Grant->WinStaAdded);
    if (dwError == ERROR_SUCCESS)
        dwError = AllowSid(hDesktop, Sid, GRANT_DESKTOP_ACCESS, &Grant->DesktopAdded);
    if (dwError != ERROR_SUCCESS)
    {
        if (Grant->WinStaAdded)
            RevokeSid(hWinSta, Sid);
        HeapFree(GetProcessHeap(), 0, Grant);
        Grant = NULL;
    }
    else
    {
        InsertTailList(&DesktopGrantList, &Grant->ListEntry);
    }
    CloseDesktopPath(hWinSta, hDesktop);

done:
    LeaveCriticalSection(&DesktopAccessLock);
    HeapFree(GetProcessHeap(), 0, SidBuffer);
    *pdwError = dwError;
    return Grant;
}

static
VOID
ReleaseDesktopGrant(
    _In_ PDESKTOP_GRANT Grant)
{
    HWINSTA hWinSta;
    HDESK hDesktop;

    EnterCriticalSection(&DesktopAccessLock);
    if (--Grant->Count != 0)
    {
        LeaveCriticalSection(&DesktopAccessLock);
        return;
    }
    RemoveEntryList(&Grant->ListEntry);
    OpenDesktopPath(Grant->Path, READ_CONTROL | WRITE_DAC | WINSTA_ENUMDESKTOPS, READ_CONTROL | WRITE_DAC,
                    &hWinSta, &hDesktop);
    if (hDesktop && Grant->DesktopAdded)
        RevokeSid(hDesktop, Grant->Sid);
    if (hWinSta && Grant->WinStaAdded)
        RevokeSid(hWinSta, Grant->Sid);
    CloseDesktopPath(hWinSta, hDesktop);
    LeaveCriticalSection(&DesktopAccessLock);
    HeapFree(GetProcessHeap(), 0, Grant);
}

static
VOID
FinishDesktopGrantWait(
    _In_ PDESKTOP_GRANT_WAIT Wait)
{
    if (InterlockedDecrement(&Wait->Owners) != 0)
        return;
    UnregisterWait(Wait->hWait);
    ReleaseDesktopGrant(Wait->Grant);
    CloseHandle(Wait->hProcess);
    HeapFree(GetProcessHeap(), 0, Wait);
}

static
VOID
CALLBACK
DesktopGrantProcessExited(
    _In_ PVOID Context,
    _In_ BOOLEAN TimedOut)
{
    UNREFERENCED_PARAMETER(TimedOut);
    FinishDesktopGrantWait(Context);
}

/* Keeps Grant until hProcess exits; FALSE leaves Grant with the caller */
static
BOOL
WatchDesktopGrant(
    _In_ PDESKTOP_GRANT Grant,
    _In_ HANDLE hProcess)
{
    PDESKTOP_GRANT_WAIT Wait;

    Wait = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Wait));
    if (Wait == NULL)
        return FALSE;
    if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &Wait->hProcess,
                         SYNCHRONIZE, FALSE, 0))
    {
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }
    Wait->Grant = Grant;
    Wait->Owners = 2;
    if (!RegisterWaitForSingleObject(&Wait->hWait, Wait->hProcess, DesktopGrantProcessExited,
                                     Wait, INFINITE, WT_EXECUTEONLYONCE))
    {
        CloseHandle(Wait->hProcess);
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }
    FinishDesktopGrantWait(Wait);
    return TRUE;
}


void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}


void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}


DWORD
StartRpcServer(VOID)
{
    NTSTATUS Status;

    Status = lpServiceGlobals->StartRpcServer(L"seclogon", ISeclogon_v1_0_s_ifspec);
    TRACE("StartRpcServer returned 0x%08lx\n", Status);

    return RtlNtStatusToDosError(Status);
}


DWORD
StopRpcServer(VOID)
{
    NTSTATUS Status;

    Status = lpServiceGlobals->StopRpcServer(ISeclogon_v1_0_s_ifspec);
    TRACE("StopRpcServer returned 0x%08lx\n", Status);

    return RtlNtStatusToDosError(Status);
}


/* A token handed over by the caller is used only for a caller that may impersonate (CreateProcessWithTokenW) */
static
BOOL
SeclTakeCallerToken(
    _In_ handle_t hBinding,
    _In_ SECL_REQUEST *pRequest,
    _Out_ PHANDLE phToken)
{
    PRIVILEGE_SET Privilege;
    HANDLE hClientToken = NULL;
    HANDLE hCallerProcess = NULL;
    HANDLE hCallerToken = NULL;
    BOOL bHeld = FALSE;
    BOOL bTaken = FALSE;
    DWORD dwError = ERROR_PRIVILEGE_NOT_HELD;
    BOOL bResult;

    *phToken = NULL;

    Privilege.PrivilegeCount = 1;
    Privilege.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privilege.Privilege[0].Attributes = 0;
    if (!LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &Privilege.Privilege[0].Luid))
        return FALSE;

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hClientToken))
    {
        if (!PrivilegeCheck(hClientToken, &Privilege, &bHeld))
            bHeld = FALSE;
        CloseHandle(hClientToken);
    }

    /* The handle is taken as the caller, so it comes only from a process the caller could take it from itself */
    if (bHeld)
    {
        hCallerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pRequest->dwProcessId);
        bTaken = hCallerProcess != NULL &&
                 DuplicateHandle(hCallerProcess,
                                 (HANDLE)pRequest->hToken,
                                 GetCurrentProcess(),
                                 &hCallerToken,
                                 0,
                                 FALSE,
                                 DUPLICATE_SAME_ACCESS);
        dwError = GetLastError();
        if (hCallerProcess != NULL)
            CloseHandle(hCallerProcess);
    }

    RpcRevertToSelf();

    if (!bTaken)
    {
        SetLastError(dwError);
        return FALSE;
    }

    bResult = DuplicateTokenEx(hCallerToken,
                               MAXIMUM_ALLOWED,
                               NULL,
                               SecurityImpersonation,
                               TokenPrimary,
                               phToken);
    CloseHandle(hCallerToken);

    return bResult;
}


/* The caller's process is opened as the caller and its session read from its own token, never from what the request names */
static
BOOL
SeclOpenCaller(
    _In_ handle_t hBinding,
    _In_ DWORD dwProcessId,
    _Out_ PHANDLE phProcess,
    _Out_ PDWORD pdwSessionId)
{
    HANDLE hClientToken = NULL;
    DWORD dwLength;
    DWORD dwError;

    *phProcess = NULL;
    *pdwSessionId = 0;

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hClientToken) &&
        GetTokenInformation(hClientToken, TokenSessionId, pdwSessionId, sizeof(*pdwSessionId), &dwLength))
    {
        *phProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
    }
    dwError = GetLastError();

    if (hClientToken != NULL)
        CloseHandle(hClientToken);

    RpcRevertToSelf();

    SetLastError(dwError);
    return *phProcess != NULL;
}


/* The token of the RPC client itself, never that of a process the request names */
static
BOOL
SeclClientPrimaryToken(
    _In_ handle_t hBinding,
    _Out_ PHANDLE phToken)
{
    HANDLE hClientToken = NULL;
    DWORD dwError;
    BOOL bResult;

    *phToken = NULL;

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    bResult = OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hClientToken);
    dwError = GetLastError();
    RpcRevertToSelf();

    if (!bResult)
    {
        SetLastError(dwError);
        return FALSE;
    }

    bResult = DuplicateTokenEx(hClientToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                               TokenPrimary, phToken);
    CloseHandle(hClientToken);
    return bResult;
}


VOID
__stdcall
SeclCreateProcessWithLogonW(
    _In_ handle_t hBinding,
    _In_ SECL_REQUEST *pRequest,
    _Out_ SECL_RESPONSE *pResponse)
{
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo = {0};

    PROFILEINFOW ProfileInfo;
    HANDLE hToken = NULL;
    PDESKTOP_GRANT Grant = NULL;
    HANDLE hTargetProcessHandle = NULL;
    PVOID Environment = NULL;
    DWORD CreationFlags;
    DWORD SessionId;

    ULONG dwError = ERROR_SUCCESS;
    BOOL rc;

    TRACE("SeclCreateProcessWithLogonW(%p %p %p)\n", hBinding, pRequest, pResponse);

    ZeroMemory(&ProfileInfo, sizeof(ProfileInfo));
    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

    if (pRequest != NULL)
    {
        TRACE("Username: '%S'\n", pRequest->Username);
        TRACE("Domain: '%S'\n", pRequest->Domain);
        TRACE("ApplicationName: '%S'\n", pRequest->ApplicationName);
        TRACE("CommandLine: '%S'\n", pRequest->CommandLine);
        TRACE("CurrentDirectory: '%S'\n", pRequest->CurrentDirectory);
        TRACE("LogonFlags: 0x%lx\n", pRequest->dwLogonFlags);
        TRACE("CreationFlags: 0x%lx\n", pRequest->dwCreationFlags);
        TRACE("ProcessId: %lu\n", pRequest->dwProcessId);
    }

    if (!SeclOpenCaller(hBinding, pRequest->dwProcessId, &hTargetProcessHandle, &SessionId))
    {
        dwError = GetLastError();
        WARN("Opening the caller failed with Error %lu\n", dwError);
        goto done;
    }

    ZeroMemory(&ProfileInfo, sizeof(ProfileInfo));

    /* Logon */
    if (pRequest->hToken != 0)
    {
        rc = SeclTakeCallerToken(hBinding,
                                 pRequest,
                                 &hToken);
    }
    else if (pRequest->dwLogonFlags & LOGON_NETCREDENTIALS_ONLY)
    {
        /* FIXME: the credentials are not attached to the new process for network access */
        rc = SeclClientPrimaryToken(hBinding, &hToken);
    }
    else
    {
        rc = LogonUser(pRequest->Username,
                       pRequest->Domain,
                       pRequest->Password,
                       LOGON32_LOGON_INTERACTIVE,
                       LOGON32_PROVIDER_DEFAULT,
                       &hToken);
    }
    if (rc == FALSE)
    {
        dwError = GetLastError();
        WARN("Getting the token failed with Error %lu\n", dwError);
        goto done;
    }

    /* The shell's elevation path: a logon that was split runs with its full token,
     * unless the policy refuses standard users an elevation (then nobody gets it this way) */
    if ((pRequest->dwLogonFlags & SECL_LOGON_ELEVATE) && pRequest->hToken == 0 &&
        !(pRequest->dwLogonFlags & LOGON_NETCREDENTIALS_ONLY) && !IsUserElevationDenied())
    {
        TOKEN_LINKED_TOKEN Linked = { NULL };
        DWORD Type = 0, LinkedLength;

        if (GetTokenInformation(hToken, TokenElevationType, &Type, sizeof(Type), &LinkedLength) &&
            Type == TokenElevationTypeLimited &&
            GetTokenInformation(hToken, TokenLinkedToken, &Linked, sizeof(Linked), &LinkedLength) &&
            Linked.LinkedToken != NULL)
        {
            CloseHandle(hToken);
            hToken = Linked.LinkedToken;
        }
    }

    if (!SetTokenInformation(hToken, TokenSessionId, &SessionId, sizeof(SessionId)))
    {
        dwError = GetLastError();
        WARN("Setting the token session failed with Error %lu\n", dwError);
        goto done;
    }

    /* Load the user profile */
    if (pRequest->dwLogonFlags & LOGON_WITH_PROFILE)
    {
        ProfileInfo.dwSize = sizeof(ProfileInfo);
        ProfileInfo.lpUserName = pRequest->Username;

        rc = LoadUserProfileW(hToken,
                              &ProfileInfo);
        if (rc == FALSE)
        {
            dwError = GetLastError();
            WARN("LoadUserProfile() failed with Error %lu\n", dwError);
            goto done;
        }
    }

    /* Initialize the startup information */
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.lpDesktop = pRequest->Desktop ? pRequest->Desktop : L"WinSta0\\Default";
    if (pRequest->dwDesktopInherited)
    {
        Grant = GrantDesktopAccess(hBinding, hToken, StartupInfo.lpDesktop, &dwError);
        if (Grant == NULL)
            WARN("Granting access to %S failed with Error %lu\n", StartupInfo.lpDesktop, dwError);
        dwError = ERROR_SUCCESS;
    }

    /* FIXME: Get the rest of the startup info from the caller */

    CreationFlags = pRequest->dwCreationFlags;
    if (pRequest->Environment == NULL)
    {
        if (!CreateEnvironmentBlock(&Environment, hToken, FALSE))
        {
            dwError = GetLastError();
            WARN("CreateEnvironmentBlock() failed with Error %lu\n", dwError);
            goto done;
        }
        CreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    /* Create Process */
    rc = CreateProcessAsUserW(hToken,
                              pRequest->ApplicationName,
                              pRequest->CommandLine,
                              NULL,  // lpProcessAttributes,
                              NULL,  // lpThreadAttributes,
                              FALSE, // bInheritHandles,
                              CreationFlags,
                              Environment ? Environment : pRequest->Environment,
                              pRequest->CurrentDirectory,
                              &StartupInfo,
                              &ProcessInfo);
    if (rc == FALSE)
    {
        dwError = GetLastError();
        WARN("CreateProcessAsUser() failed with Error %lu\n", dwError);
        goto done;
    }

    if (Grant && WatchDesktopGrant(Grant, ProcessInfo.hProcess))
        Grant = NULL;

    /* Return process info to the caller */
    if (pResponse != NULL)
    {
        DuplicateHandle(GetCurrentProcess(),
                        ProcessInfo.hProcess,
                        hTargetProcessHandle,
                        (PHANDLE)&pResponse->hProcess,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS);

        DuplicateHandle(GetCurrentProcess(),
                        ProcessInfo.hThread,
                        hTargetProcessHandle,
                        (PHANDLE)&pResponse->hThread,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS);

        pResponse->dwProcessId = ProcessInfo.dwProcessId;
        pResponse->dwThreadId = ProcessInfo.dwThreadId;
    }

done:
    if (hTargetProcessHandle)
        CloseHandle(hTargetProcessHandle);

    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);

    if (ProcessInfo.hProcess)
        CloseHandle(ProcessInfo.hProcess);

    if (Grant != NULL)
        ReleaseDesktopGrant(Grant);

    if (Environment != NULL)
        DestroyEnvironmentBlock(Environment);

    if (ProfileInfo.hProfile != NULL)
        UnloadUserProfile(hToken, ProfileInfo.hProfile);

    if (hToken != NULL)
        CloseHandle(hToken);

    if (pResponse != NULL)
        pResponse->dwError = dwError;
}

/* ELEVATION BROKER *********************************************************/

#define SECL_UAC_POLICY_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define SECL_ELEVATED_PROCESS_ACCESS (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
#define SECL_ALLOWED_CREATION_FLAGS (CREATE_NEW_CONSOLE | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | \
                                     DETACHED_PROCESS | CREATE_DEFAULT_ERROR_MODE | CREATE_BREAKAWAY_FROM_JOB)

#ifndef TokenElevationTypeLimited
#define TokenElevationTypeLimited 3
#endif

typedef struct _PENDING_PROMPT
{
    LIST_ENTRY ListEntry;
    LUID LogonId;
} PENDING_PROMPT, *PPENDING_PROMPT;

static LIST_ENTRY PendingPromptList = { &PendingPromptList, &PendingPromptList };
static INIT_ONCE PendingPromptInit = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION PendingPromptLock;

static
BOOL
CALLBACK
InitPendingPromptLock(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
{
    InitializeCriticalSection(&PendingPromptLock);
    return TRUE;
}

/* The winlogon of the caller's session holds the secure desktop around the prompt. The answer
 * of Begin is never trusted alone: consent.exe is started on WinSta0\Winlogon by that fixed
 * name, and the binding asks for identification only. Any failure refuses the request. */
#define SECL_SECURE_DESKTOP L"WinSta0\\Winlogon"

static
DWORD
SecureDesktopBegin(
    _In_ DWORD SessionId,
    _In_ DWORD TimeoutMs,
    _Out_ handle_t *phBinding)
{
    RPC_SECURITY_QOS Qos = { RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_DEFAULT,
                             RPC_C_QOS_IDENTITY_STATIC, RPC_C_IMP_LEVEL_IDENTIFY };
    WCHAR Endpoint[64];
    RPC_WSTR StringBinding = NULL;
    handle_t hBinding = NULL;
    DWORD dwError;

    *phBinding = NULL;
    StringCchPrintfW(Endpoint, _countof(Endpoint), L"wlsecdesk-%lu", SessionId);
    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)Endpoint, NULL, &StringBinding) != RPC_S_OK)
        return ERROR_ACCESS_DENIED;
    if (RpcBindingFromStringBindingW(StringBinding, &hBinding) != RPC_S_OK)
    {
        RpcStringFreeW(&StringBinding);
        return ERROR_ACCESS_DENIED;
    }
    RpcStringFreeW(&StringBinding);
    /* Identification only: whatever answers must not get to act as the service; in our
     * runtime this call is what opens the pipe with SECURITY_IDENTIFICATION, so without
     * it there is no prompt */
    if (RpcBindingSetAuthInfoExW(hBinding, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_WINNT, NULL, 0, &Qos) != RPC_S_OK)
    {
        ERR("The secure-desktop binding cannot be set to identification level\n");
        RpcBindingFree(&hBinding);
        return ERROR_ACCESS_DENIED;
    }

    RpcTryExcept
    {
        dwError = WlSecureDesktopBegin(hBinding, TimeoutMs);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RpcExceptionCode();
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        RpcBindingFree(&hBinding);
        return dwError;
    }
    *phBinding = hBinding;
    return ERROR_SUCCESS;
}

static
VOID
SecureDesktopEnd(
    _In_ handle_t hBinding)
{
    DWORD dwError;

    RpcTryExcept
    {
        dwError = WlSecureDesktopEnd(hBinding);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RpcExceptionCode();
    }
    RpcEndExcept;
    if (dwError != ERROR_SUCCESS)
        ERR("The secure desktop could not be released: Error %lu (winlogon returns on its own)\n", dwError);
    RpcBindingFree(&hBinding);
}

/* Declined or timed-out requests are counted per process and per logon session: a
 * process that just declined waits a few seconds, three in a minute wait a minute.
 * A request the user answers with Yes resets both. */
#define SECL_DECLINE_HOLD_MS     (3 * 1000)
#define SECL_DECLINE_WINDOW_MS   (60 * 1000)
#define SECL_DECLINE_LIMIT       3
#define SECL_DECLINE_ENTRIES     32

typedef struct _DECLINE_ENTRY
{
    DWORD Pid;
    LUID LogonId;
    DWORD Tick;
} DECLINE_ENTRY;

static DECLINE_ENTRY DeclineRing[SECL_DECLINE_ENTRIES];
static ULONG DeclineNext;

/* Called with PendingPromptLock held */
static
BOOL
IsRequestLimited(
    _In_ DWORD Pid,
    _In_ PLUID LogonId)
{
    DWORD Now = GetTickCount(), ByPid = 0, ByLogon = 0;
    ULONG i;

    for (i = 0; i < SECL_DECLINE_ENTRIES; i++)
    {
        if (DeclineRing[i].Tick == 0 || Now - DeclineRing[i].Tick > SECL_DECLINE_WINDOW_MS)
            continue;
        if (DeclineRing[i].Pid == Pid)
        {
            ByPid++;
            if (Now - DeclineRing[i].Tick < SECL_DECLINE_HOLD_MS)
                return TRUE;
        }
        if (RtlEqualLuid(&DeclineRing[i].LogonId, LogonId))
            ByLogon++;
    }
    return ByPid >= SECL_DECLINE_LIMIT || ByLogon >= SECL_DECLINE_LIMIT;
}

static
VOID
RecordRequestResult(
    _In_ DWORD Pid,
    _In_ PLUID LogonId,
    _In_ BOOL Declined)
{
    ULONG i;

    EnterCriticalSection(&PendingPromptLock);
    if (Declined)
    {
        DeclineRing[DeclineNext].Pid = Pid;
        DeclineRing[DeclineNext].LogonId = *LogonId;
        DeclineRing[DeclineNext].Tick = GetTickCount() | 1;
        DeclineNext = (DeclineNext + 1) % SECL_DECLINE_ENTRIES;
    }
    else
    {
        for (i = 0; i < SECL_DECLINE_ENTRIES; i++)
        {
            if (DeclineRing[i].Pid == Pid || RtlEqualLuid(&DeclineRing[i].LogonId, LogonId))
                DeclineRing[i].Tick = 0;
        }
    }
    LeaveCriticalSection(&PendingPromptLock);
}

/* One prompt per logon session at a time */
static
PPENDING_PROMPT
BeginPrompt(
    _In_ DWORD CallerPid,
    _In_ PLUID LogonId)
{
    PLIST_ENTRY Entry;
    PPENDING_PROMPT Prompt;

    InitOnceExecuteOnce(&PendingPromptInit, InitPendingPromptLock, NULL, NULL);
    EnterCriticalSection(&PendingPromptLock);
    if (IsRequestLimited(CallerPid, LogonId))
    {
        LeaveCriticalSection(&PendingPromptLock);
        return NULL;
    }
    for (Entry = PendingPromptList.Flink; Entry != &PendingPromptList; Entry = Entry->Flink)
    {
        Prompt = CONTAINING_RECORD(Entry, PENDING_PROMPT, ListEntry);
        if (RtlEqualLuid(&Prompt->LogonId, LogonId))
        {
            LeaveCriticalSection(&PendingPromptLock);
            return NULL;
        }
    }
    Prompt = HeapAlloc(GetProcessHeap(), 0, sizeof(*Prompt));
    if (Prompt != NULL)
    {
        Prompt->LogonId = *LogonId;
        InsertTailList(&PendingPromptList, &Prompt->ListEntry);
    }
    LeaveCriticalSection(&PendingPromptLock);
    return Prompt;
}

static
VOID
EndPrompt(
    _In_ PPENDING_PROMPT Prompt)
{
    EnterCriticalSection(&PendingPromptLock);
    RemoveEntryList(&Prompt->ListEntry);
    LeaveCriticalSection(&PendingPromptLock);
    HeapFree(GetProcessHeap(), 0, Prompt);
}

static
DWORD
ReadPolicyDword(
    _In_ PCWSTR ValueName,
    _In_ DWORD Default)
{
    HKEY hKey;
    DWORD Value, Size = sizeof(Value), Type;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECL_UAC_POLICY_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return Default;
    if (RegQueryValueExW(hKey, ValueName, NULL, &Type, (LPBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD || Size != sizeof(Value))
    {
        Value = Default;
    }
    RegCloseKey(hKey);
    return Value;
}

/* ConsentPromptBehaviorUser 0: a standard user gets no elevation at all */
static
BOOL
IsUserElevationDenied(VOID)
{
    return ReadPolicyDword(L"EnableLUA", 0) != 0 && ReadPolicyDword(L"ConsentPromptBehaviorUser", 3) == 0;
}

static
BOOL
GetTokenDword(
    _In_ HANDLE hToken,
    _In_ TOKEN_INFORMATION_CLASS Class,
    _Out_ PDWORD Value)
{
    DWORD Length;

    *Value = 0;
    return GetTokenInformation(hToken, Class, Value, sizeof(*Value), &Length);
}

static
BOOL
GetTokenLogonId(
    _In_ HANDLE hToken,
    _Out_ PLUID LogonId)
{
    TOKEN_STATISTICS Statistics;
    DWORD Length;

    if (!GetTokenInformation(hToken, TokenStatistics, &Statistics, sizeof(Statistics), &Length))
        return FALSE;
    *LogonId = Statistics.AuthenticationId;
    return TRUE;
}

static
DWORD
GetTokenIntegrityRid(
    _In_ HANDLE hToken)
{
    BYTE Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    DWORD Length;

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, Label, sizeof(Buffer), &Length))
        return 0;
    return *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
}

static
BOOL
SameTokenUser(
    _In_ HANDLE hToken1,
    _In_ HANDLE hToken2)
{
    BYTE Buffer1[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE], Buffer2[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD Length;

    if (!GetTokenInformation(hToken1, TokenUser, Buffer1, sizeof(Buffer1), &Length) ||
        !GetTokenInformation(hToken2, TokenUser, Buffer2, sizeof(Buffer2), &Length))
    {
        return FALSE;
    }
    return EqualSid(((PTOKEN_USER)Buffer1)->User.Sid, ((PTOKEN_USER)Buffer2)->User.Sid);
}

/* The table of callers the broker serves: an interactive logon, Medium or above, not
 * sandboxed or restricted, and (for the process token) the limited side of a pair. */
static
DWORD
CheckElevationCallerToken(
    _In_ HANDLE hToken,
    _In_ BOOL RequireLimited)
{
    LUID LogonId;
    DWORD Value;

    if (IsServiceAccountToken(hToken))
        return ERROR_ACCESS_DENIED;
    if (!GetTokenLogonId(hToken, &LogonId) || (LogonId.HighPart == 0 && LogonId.LowPart <= 999))
        return ERROR_ACCESS_DENIED;
    if (GetTokenIntegrityRid(hToken) < SECURITY_MANDATORY_MEDIUM_RID)
        return ERROR_ACCESS_DENIED;
    /* A sandbox question the kernel cannot answer is a refusal, not a pass */
    if (!GetTokenDword(hToken, TokenIsAppContainer, &Value) || Value != 0)
        return ERROR_ACCESS_DENIED;
    SetLastError(ERROR_SUCCESS);
    if (IsTokenRestricted(hToken) || GetLastError() != ERROR_SUCCESS)
        return ERROR_ACCESS_DENIED;
    if (!GetTokenDword(hToken, TokenSandBoxInert, &Value) || Value != 0)
        return ERROR_ACCESS_DENIED;
    if (RequireLimited &&
        (!GetTokenDword(hToken, TokenElevationType, &Value) || Value != TokenElevationTypeLimited))
    {
        return ERROR_ELEVATION_REQUIRED;
    }
    return ERROR_SUCCESS;
}

/* The caller is the local process behind the pipe: its primary token decides, and the
 * thread that called must belong to the same logon and user at impersonation level. */
static
DWORD
OpenElevationCaller(
    _In_ handle_t hBinding,
    _Out_ PHANDLE phProcess,
    _Out_ PHANDLE phToken,
    _Out_ PLUID LogonId,
    _Out_ PDWORD pdwSessionId,
    _Out_ PDWORD pdwProcessId)
{
    HANDLE hProcess = NULL, hToken = NULL, hThreadToken = NULL;
    ULONG ClientPid;
    LUID ThreadLogonId;
    DWORD Level, Length, dwError = ERROR_ACCESS_DENIED;

    *phProcess = NULL;
    *phToken = NULL;

    if (I_RpcBindingInqLocalClientPID(hBinding, &ClientPid) != RPC_S_OK)
        return ERROR_ACCESS_DENIED;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, ClientPid);
    if (hProcess == NULL)
        return ERROR_ACCESS_DENIED;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
        goto done;

    /* Limited or not: the policy table in the request decides what each caller gets */
    dwError = CheckElevationCallerToken(hToken, FALSE);
    if (dwError != ERROR_SUCCESS)
        goto done;

    dwError = ERROR_ACCESS_DENIED;
    if (!GetTokenLogonId(hToken, LogonId) ||
        !GetTokenInformation(hToken, TokenSessionId, pdwSessionId, sizeof(*pdwSessionId), &Length))
    {
        goto done;
    }

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
        goto done;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken) &&
        GetTokenInformation(hThreadToken, TokenImpersonationLevel, &Level, sizeof(Level), &Length) &&
        Level >= SecurityImpersonation &&
        CheckElevationCallerToken(hThreadToken, FALSE) == ERROR_SUCCESS &&
        GetTokenLogonId(hThreadToken, &ThreadLogonId) &&
        RtlEqualLuid(&ThreadLogonId, LogonId) &&
        SameTokenUser(hThreadToken, hToken))
    {
        dwError = ERROR_SUCCESS;
    }
    RpcRevertToSelf();

done:
    if (hThreadToken != NULL)
        CloseHandle(hThreadToken);
    if (dwError == ERROR_SUCCESS)
    {
        *phProcess = hProcess;
        *phToken = hToken;
        *pdwProcessId = ClientPid;
    }
    else
    {
        if (hToken != NULL)
            CloseHandle(hToken);
        CloseHandle(hProcess);
    }
    return dwError;
}

/* The image is resolved and opened once, as the caller, with no write or delete sharing;
 * the final path of that handle is what is shown and what runs. A drive letter of the
 * user's own making is followed to the file's real place; network drives and removable
 * media are refused. */
static
DWORD
OpenElevationImage(
    _In_ handle_t hBinding,
    _In_opt_ PCWSTR ApplicationName,
    _In_opt_ PCWSTR CommandLine,
    _In_opt_ PCWSTR CurrentDirectory,
    _Out_ PHANDLE phFile,
    _Out_writes_(FinalPathChars) PWSTR FinalPath,
    _In_ DWORD FinalPathChars)
{
    WCHAR Candidate[MAX_PATH], Found[MAX_PATH], Drive[3] = L"?:", Target[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwError = ERROR_SUCCESS, Length;
    PCWSTR Source, End;

    *phFile = NULL;
    FinalPath[0] = UNICODE_NULL;

    if (ApplicationName != NULL && ApplicationName[0] != UNICODE_NULL)
    {
        if (FAILED(StringCchCopyW(Candidate, _countof(Candidate), ApplicationName)))
            return ERROR_FILENAME_EXCED_RANGE;
    }
    else if (CommandLine != NULL && CommandLine[0] != UNICODE_NULL)
    {
        Source = CommandLine;
        while (*Source == L' ' || *Source == L'\t')
            Source++;
        if (*Source == L'"')
        {
            Source++;
            End = wcschr(Source, L'"');
        }
        else
        {
            End = Source;
            while (*End != UNICODE_NULL && *End != L' ' && *End != L'\t')
                End++;
        }
        if (End == NULL || End == Source || (SIZE_T)(End - Source) >= _countof(Candidate))
            return ERROR_INVALID_PARAMETER;
        CopyMemory(Candidate, Source, (End - Source) * sizeof(WCHAR));
        Candidate[End - Source] = UNICODE_NULL;
    }
    else
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (RpcImpersonateClient(hBinding) != RPC_S_OK)
        return ERROR_ACCESS_DENIED;

    if (!SearchPathW(CurrentDirectory, Candidate, L".exe", _countof(Found), Found, NULL))
    {
        dwError = GetLastError();
    }
    else
    {
        hFile = CreateFileW(Found, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            dwError = GetLastError();
    }
    RpcRevertToSelf();

    if (dwError != ERROR_SUCCESS)
        return dwError;

    Length = GetFinalPathNameByHandleW(hFile, FinalPath, FinalPathChars, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (Length == 0 || Length >= FinalPathChars)
    {
        dwError = ERROR_BAD_PATHNAME;
        goto fail;
    }
    if (wcsncmp(FinalPath, L"\\\\?\\", 4) == 0)
        MoveMemory(FinalPath, FinalPath + 4, (Length - 4 + 1) * sizeof(WCHAR));

    /* Only a path on a fixed, system-defined drive letter is run elevated */
    if (FinalPath[1] != L':' || FinalPath[2] != L'\\')
    {
        dwError = ERROR_BAD_PATHNAME;
        goto fail;
    }
    Drive[0] = FinalPath[0];
    if (QueryDosDeviceW(Drive, Target, _countof(Target)) == 0 ||
        wcsncmp(Target, L"\\??\\", 4) == 0 ||
        wcsstr(Target, L"LanmanRedirector") != NULL ||
        wcsstr(Target, L"\\Device\\Mup") != NULL)
    {
        dwError = ERROR_BAD_PATHNAME;
        goto fail;
    }
    Target[0] = FinalPath[0];
    Target[1] = L':';
    Target[2] = L'\\';
    Target[3] = UNICODE_NULL;
    if (GetDriveTypeW(Target) != DRIVE_FIXED)
    {
        dwError = ERROR_BAD_PATHNAME;
        goto fail;
    }

    *phFile = hFile;
    return ERROR_SUCCESS;

fail:
    CloseHandle(hFile);
    FinalPath[0] = UNICODE_NULL;
    return dwError;
}

/* consent.exe runs as SYSTEM in the caller's session on the caller's desktop and
 * answers with its exit code. A prompt nobody answers ends as a refusal. */
#define CONSENT_TIMEOUT_MS  (2 * 60 * 1000)
/* The logon LSA knows for this logon id must be an interactive logon of this session */
static
BOOL
IsInteractiveLogonOfSession(
    _In_ PLUID LogonId,
    _In_ DWORD SessionId)
{
    PSECURITY_LOGON_SESSION_DATA Data = NULL;
    BOOL Match = FALSE;

    if (LsaGetLogonSessionData(LogonId, &Data) == STATUS_SUCCESS && Data != NULL)
    {
        Match = (Data->Session == SessionId && Data->LogonType == Interactive);
        LsaFreeReturnBuffer(Data);
    }
    return Match;
}

/* DOMAIN\user of the token, or its SID as text when the name is not known or could not
 * travel as one quoted argument; FALSE when neither can be read */
static
BOOL
GetTokenAccountName(
    _In_ HANDLE hToken,
    _Out_writes_(Chars) PWSTR Account,
    _In_ DWORD Chars)
{
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    WCHAR Name[256], Domain[256];
    DWORD Length, NameChars = _countof(Name), DomainChars = _countof(Domain);
    SID_NAME_USE Use;
    PWSTR SidText = NULL;
    BOOL Named = FALSE;

    Account[0] = UNICODE_NULL;
    if (!GetTokenInformation(hToken, TokenUser, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    if (LookupAccountSidW(NULL, User->User.Sid, Name, &NameChars, Domain, &DomainChars, &Use) &&
        wcschr(Name, L'"') == NULL && wcschr(Domain, L'"') == NULL)
    {
        Named = SUCCEEDED(StringCchPrintfW(Account, Chars, L"%ls\\%ls", Domain, Name));
    }
    if (!Named && ConvertSidToStringSidW(User->User.Sid, &SidText))
    {
        Named = SUCCEEDED(StringCchCopyW(Account, Chars, SidText));
        LocalFree(SidText);
    }
    return Named;
}

/* An elevated process that runs as another account than the caller's (the credentials were
 * that account's) gets that account's profile, as the logon path does; the same account
 * already has its profile loaded by its logon */
static
DWORD
LoadProfileWhenOtherUser(
    _In_ HANDLE hCaller,
    _In_ HANDLE hElevated,
    _Out_writes_(NameChars) PWSTR Name,
    _In_ DWORD NameChars,
    _Inout_ LPPROFILEINFOW ProfileInfo)
{
    UCHAR CallerBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    UCHAR ElevatedBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER Caller = (PTOKEN_USER)CallerBuffer, Elevated = (PTOKEN_USER)ElevatedBuffer;
    WCHAR Domain[256];
    DWORD Length, DomainChars = _countof(Domain);
    SID_NAME_USE Use;

    if (!GetTokenInformation(hCaller, TokenUser, CallerBuffer, sizeof(CallerBuffer), &Length) ||
        !GetTokenInformation(hElevated, TokenUser, ElevatedBuffer, sizeof(ElevatedBuffer), &Length))
    {
        return GetLastError();
    }
    if (EqualSid(Caller->User.Sid, Elevated->User.Sid))
        return ERROR_SUCCESS;
    if (!LookupAccountSidW(NULL, Elevated->User.Sid, Name, &NameChars, Domain, &DomainChars, &Use))
        return GetLastError();
    ProfileInfo->dwSize = sizeof(*ProfileInfo);
    ProfileInfo->lpUserName = Name;
    if (!LoadUserProfileW(hElevated, ProfileInfo))
    {
        ProfileInfo->hProfile = NULL;
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

static
DWORD
AskConsent(
    _In_ DWORD SessionId,
    _In_ PCWSTR DesktopPath,
    _In_ PCWSTR Account,
    _In_ PCWSTR FinalPath,
    _In_ PCWSTR CommandLine,
    _In_ DWORD_PTR hwndOwner,
    _Out_ PBOOL Allowed)
{
    HANDLE hSelf = NULL, hSystem = NULL;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo = { 0 };
    WCHAR Exe[MAX_PATH];
    PWSTR Cmd = NULL;
    SIZE_T CmdChars;
    DWORD ExitCode = IDNO, dwError = ERROR_SUCCESS;

    *Allowed = FALSE;

    if (!GetSystemDirectoryW(Exe, _countof(Exe)) ||
        FAILED(StringCchCatW(Exe, _countof(Exe), L"\\consent.exe")))
    {
        return ERROR_BAD_PATHNAME;
    }

    CmdChars = wcslen(Exe) + wcslen(Account) + wcslen(FinalPath) + (CommandLine ? wcslen(CommandLine) : 0) + 64;
    Cmd = HeapAlloc(GetProcessHeap(), 0, CmdChars * sizeof(WCHAR));
    if (Cmd == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    StringCchPrintfW(Cmd, CmdChars, L"\"%ls\" %Ix \"%ls\" \"%ls\" %ls", Exe, hwndOwner, Account, FinalPath,
                     CommandLine ? CommandLine : L"");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hSelf) ||
        !DuplicateTokenEx(hSelf, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystem) ||
        !SetTokenInformation(hSystem, TokenSessionId, &SessionId, sizeof(SessionId)))
    {
        dwError = GetLastError();
        goto done;
    }

    StartupInfo.lpDesktop = (LPWSTR)DesktopPath;
    if (!CreateProcessAsUserW(hSystem, Exe, Cmd, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT,
                              NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        dwError = GetLastError();
        goto done;
    }
    if (WaitForSingleObject(ProcessInfo.hProcess, CONSENT_TIMEOUT_MS) != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, IDNO);
        WaitForSingleObject(ProcessInfo.hProcess, 5000);
    }
    else if (GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode))
    {
        *Allowed = (ExitCode == IDYES);
    }
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

done:
    if (hSystem != NULL)
        CloseHandle(hSystem);
    if (hSelf != NULL)
        CloseHandle(hSelf);
    HeapFree(GetProcessHeap(), 0, Cmd);
    return dwError;
}

/* The groups of a token: Administrators present and enabled */
static
BOOL
TokenHasEnabledAdministrators(
    _In_ HANDLE hToken)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    PTOKEN_GROUPS Groups = NULL;
    PSID AdminsSid = NULL;
    DWORD Length = 0, i;
    BOOL Found = FALSE;

    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Length);
    if (Length == 0 || (Groups = HeapAlloc(GetProcessHeap(), 0, Length)) == NULL)
        return FALSE;
    if (GetTokenInformation(hToken, TokenGroups, Groups, Length, &Length) &&
        AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &AdminsSid))
    {
        for (i = 0; i < Groups->GroupCount && !Found; i++)
        {
            Found = (Groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                    !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
                    EqualSid(Groups->Groups[i].Sid, AdminsSid);
        }
        FreeSid(AdminsSid);
    }
    HeapFree(GetProcessHeap(), 0, Groups);
    return Found;
}

/* The token a logon will really run with (the linked one when the logon is split),
 * accepted only if it is an administrator's */
static
DWORD
AdministratorTokenOfLogon(
    _In_ HANDLE hLogon,
    _Out_ PHANDLE phUse)
{
    TOKEN_LINKED_TOKEN LogonLinked = { NULL };
    DWORD Type = 0, Length;
    HANDLE hUse = hLogon;

    *phUse = NULL;
    if (GetTokenDword(hLogon, TokenElevationType, &Type) && Type == TokenElevationTypeLimited)
    {
        if (!GetTokenInformation(hLogon, TokenLinkedToken, &LogonLinked, sizeof(LogonLinked), &Length) ||
            LogonLinked.LinkedToken == NULL)
        {
            return ERROR_ACCESS_DENIED;
        }
        hUse = LogonLinked.LinkedToken;
    }
    if (!TokenHasEnabledAdministrators(hUse))
    {
        if (hUse != hLogon)
            CloseHandle(hUse);
        return ERROR_ACCESS_DENIED;
    }
    *phUse = hUse;
    return ERROR_SUCCESS;
}

static INIT_ONCE ConsentInheritInit = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION ConsentInheritLock;

static
BOOL
CALLBACK
InitConsentInheritLock(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
{
    InitializeCriticalSection(&ConsentInheritLock);
    return TRUE;
}

#define SECL_CREDENTIAL_TRIES 3

static
VOID
SendVerdict(
    _In_ HANDLE hVerdict,
    _In_ CONSENT_VERDICT Verdict)
{
    ULONG Value = Verdict;
    DWORD Written;
    WriteFile(hVerdict, &Value, sizeof(Value), &Written, NULL);
}

/* Waits for one whole record, or for consent to be gone, within the prompt's timeout */
static
BOOL
ReadRecord(
    _In_ HANDLE hRecord,
    _In_ HANDLE hConsent,
    _In_ DWORD Start,
    _Out_ PCONSENT_CREDENTIAL_RECORD Record)
{
    DWORD Available, Read;

    for (;;)
    {
        if (!PeekNamedPipe(hRecord, NULL, 0, NULL, &Available, NULL))
            return FALSE;
        if (Available >= sizeof(*Record))
            break;
        if (WaitForSingleObject(hConsent, 100) == WAIT_OBJECT_0 ||
            GetTickCount() - Start > CONSENT_TIMEOUT_MS)
        {
            return FALSE;
        }
    }
    if (!ReadFile(hRecord, Record, sizeof(*Record), &Read, NULL) || Read != sizeof(*Record))
        return FALSE;
    /* Nothing from consent is trusted for its shape, SYSTEM or not */
    if (Record->Magic != CONSENT_RECORD_MAGIC ||
        Record->UserLength >= CONSENT_MAX_USER || Record->DomainLength >= CONSENT_MAX_DOMAIN ||
        Record->PasswordLength >= CONSENT_MAX_PASSWORD)
    {
        return FALSE;
    }
    Record->User[Record->UserLength] = UNICODE_NULL;
    Record->Domain[Record->DomainLength] = UNICODE_NULL;
    Record->Password[Record->PasswordLength] = UNICODE_NULL;
    return TRUE;
}

/* consent.exe in its credentials mode: the record pipe carries the typed credentials to
 * this service, the verdict pipe its answer; only this service logs on and counts the
 * tries. Only the consent process inherits its two ends, under one lock, because this
 * is the only process start of the service with handle inheritance on. */
static
DWORD
AskCredentials(
    _In_ DWORD SessionId,
    _In_ PCWSTR DesktopPath,
    _In_ PCWSTR Account,
    _In_ PCWSTR FinalPath,
    _In_ PCWSTR CommandLine,
    _In_ DWORD_PTR hwndOwner,
    _Out_ PHANDLE phToken,
    _Out_ PBOOL Allowed)
{
    SECURITY_ATTRIBUTES NoInherit = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
    HANDLE hSelf = NULL, hSystem = NULL, hRecRead = NULL, hRecWrite = NULL, hVerRead = NULL, hVerWrite = NULL;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo = { 0 };
    CONSENT_CREDENTIAL_RECORD Record;
    WCHAR Exe[MAX_PATH];
    PWSTR Cmd = NULL;
    SIZE_T CmdChars;
    DWORD Start, Tries, dwError = ERROR_SUCCESS;
    HANDLE hLogon, hUse;

    *phToken = NULL;
    *Allowed = FALSE;
    InitOnceExecuteOnce(&ConsentInheritInit, InitConsentInheritLock, NULL, NULL);

    if (!GetSystemDirectoryW(Exe, _countof(Exe)) ||
        FAILED(StringCchCatW(Exe, _countof(Exe), L"\\consent.exe")))
    {
        return ERROR_BAD_PATHNAME;
    }

    if (!CreatePipe(&hRecRead, &hRecWrite, &NoInherit, sizeof(Record)) ||
        !CreatePipe(&hVerRead, &hVerWrite, &NoInherit, sizeof(ULONG)) ||
        !SetHandleInformation(hRecWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
        !SetHandleInformation(hVerRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        dwError = GetLastError();
        goto done;
    }

    CmdChars = wcslen(Exe) + wcslen(Account) + wcslen(FinalPath) + (CommandLine ? wcslen(CommandLine) : 0) + 96;
    Cmd = HeapAlloc(GetProcessHeap(), 0, CmdChars * sizeof(WCHAR));
    if (Cmd == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    StringCchPrintfW(Cmd, CmdChars, L"\"%ls\" %Ix \"%ls\" \"%ls\" /cred:%Iu,%Iu %ls", Exe, hwndOwner, Account, FinalPath,
                     (ULONG_PTR)hRecWrite, (ULONG_PTR)hVerRead, CommandLine ? CommandLine : L"");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hSelf) ||
        !DuplicateTokenEx(hSelf, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystem) ||
        !SetTokenInformation(hSystem, TokenSessionId, &SessionId, sizeof(SessionId)))
    {
        dwError = GetLastError();
        goto done;
    }

    StartupInfo.lpDesktop = (LPWSTR)DesktopPath;
    EnterCriticalSection(&ConsentInheritLock);
    if (!CreateProcessAsUserW(hSystem, Exe, Cmd, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT,
                              NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        dwError = GetLastError();
    }
    /* The service's copies of consent's ends go at once, so nothing else can inherit them */
    CloseHandle(hRecWrite);
    hRecWrite = NULL;
    CloseHandle(hVerRead);
    hVerRead = NULL;
    LeaveCriticalSection(&ConsentInheritLock);
    if (dwError != ERROR_SUCCESS)
        goto done;

    Start = GetTickCount();
    for (Tries = 0; Tries < SECL_CREDENTIAL_TRIES; )
    {
        if (!ReadRecord(hRecRead, ProcessInfo.hProcess, Start, &Record))
            break; /* consent gone, timeout, or a malformed record: a decline */
        if (Record.Answer != IDYES)
        {
            SecureZeroMemory(&Record, sizeof(Record));
            break; /* the user declined */
        }
        if (!LogonUser(Record.User, Record.DomainLength ? Record.Domain : NULL, Record.Password,
                       LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hLogon))
        {
            SecureZeroMemory(&Record, sizeof(Record));
            Tries++;
            SendVerdict(hVerWrite, Tries < SECL_CREDENTIAL_TRIES ? ConsentVerdictWrongPassword : ConsentVerdictRefused);
            continue;
        }
        SecureZeroMemory(&Record, sizeof(Record));
        if (AdministratorTokenOfLogon(hLogon, &hUse) != ERROR_SUCCESS)
        {
            CloseHandle(hLogon);
            Tries++;
            SendVerdict(hVerWrite, Tries < SECL_CREDENTIAL_TRIES ? ConsentVerdictCannotApprove : ConsentVerdictRefused);
            continue;
        }
        if (hUse != hLogon)
            CloseHandle(hLogon);
        *phToken = hUse;
        *Allowed = TRUE;
        SendVerdict(hVerWrite, ConsentVerdictOk);
        break;
    }
    if (Tries >= SECL_CREDENTIAL_TRIES)
        dwError = ERROR_ACCESS_DENIED;

    if (WaitForSingleObject(ProcessInfo.hProcess, 5000) != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, IDNO);
        WaitForSingleObject(ProcessInfo.hProcess, 5000);
    }
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

done:
    if (hRecRead != NULL) CloseHandle(hRecRead);
    if (hRecWrite != NULL) CloseHandle(hRecWrite);
    if (hVerRead != NULL) CloseHandle(hVerRead);
    if (hVerWrite != NULL) CloseHandle(hVerWrite);
    if (hSystem != NULL) CloseHandle(hSystem);
    if (hSelf != NULL) CloseHandle(hSelf);
    if (Cmd != NULL) HeapFree(GetProcessHeap(), 0, Cmd);
    return dwError;
}

void
__stdcall
SeclCreateProcessElevatedW(
    handle_t hBinding,
    SECL_ELEVATE_REQUEST *pRequest,
    SECL_RESPONSE *pResponse)
{
    HANDLE hCallerProcess = NULL, hCallerToken = NULL, hImage = NULL;
    TOKEN_LINKED_TOKEN Linked = { NULL };
    PPENDING_PROMPT Prompt = NULL;
    PDESKTOP_GRANT Grant = NULL;
    PVOID Environment = NULL;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo = { 0 };
    WCHAR FinalPath[MAX_PATH], Account[512], ProfileUser[256];
    PROFILEINFOW ProfileInfo = { sizeof(ProfileInfo) };
    PWSTR CommandLine = NULL;
    PCWSTR Desktop;
    LUID LogonId;
    DWORD SessionId = 0, OwnSession = 0, CallerPid = 0, Policy = 0, Length, dwError;
    DWORD_PTR hwndOwner = 0;
    BOOL Allowed = FALSE, SameSession = FALSE;
    handle_t hSecureDesktop = NULL;
    PCWSTR ConsentDesktop;
    HANDLE hElevated = NULL;
    DWORD Type = 0;
    BOOL IsLimited, Credentials = FALSE;

    TRACE("SeclCreateProcessElevatedW(%p %p %p)\n", hBinding, pRequest, pResponse);

    ZeroMemory(pResponse, sizeof(*pResponse));

    dwError = OpenElevationCaller(hBinding, &hCallerProcess, &hCallerToken, &LogonId, &SessionId, &CallerPid);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* The prompt is chosen from the caller's token and the policy, never from the request:
     * a split administrator gets ConsentPromptBehaviorAdmin (0 no prompt; 2, 4, 5 consent;
     * 1, 3 credentials with the own account), a standard user ConsentPromptBehaviorUser
     * (1, 3 credentials; 0 and anything else refused). Values are Windows' own. */
    IsLimited = GetTokenDword(hCallerToken, TokenElevationType, &Type) && Type == TokenElevationTypeLimited;
    if (IsLimited)
    {
        Policy = ReadPolicyDword(L"ConsentPromptBehaviorAdmin", 5);
        Credentials = (Policy == 1 || Policy == 3);
        if (Policy > 5)
        {
            dwError = ERROR_ACCESS_DENIED;
            goto done;
        }
    }
    else
    {
        Policy = ReadPolicyDword(L"ConsentPromptBehaviorUser", 3);
        if (Policy != 1 && Policy != 3)
        {
            dwError = ERROR_ACCESS_DENIED;
            goto done;
        }
        Credentials = TRUE;
    }

    Desktop = (pRequest->Desktop && pRequest->Desktop[0]) ? pRequest->Desktop : L"WinSta0\\Default";
    SameSession = ProcessIdToSessionId(GetCurrentProcessId(), &OwnSession) && OwnSession == SessionId;
    if (SameSession)
    {
        EnterCriticalSection(&DesktopAccessLock);
        dwError = CheckClientDesktopAccess(hBinding, Desktop);
        LeaveCriticalSection(&DesktopAccessLock);
        if (dwError != ERROR_SUCCESS)
        {
            ERR("Desktop %.64S is not usable by the caller: Error %lu\n", Desktop, dwError);
            dwError = ERROR_ACCESS_DENIED;
            goto done;
        }
    }
    else if (_wcsicmp(Desktop, L"WinSta0\\Default") != 0 || !IsInteractiveLogonOfSession(&LogonId, SessionId))
    {
        /* A station name resolves in the opener's session: a caller of another session must
         * be an interactive logon of that session and is started only on its default
         * desktop, which its logon SID already admits it to; anything else is left to the
         * shell's credentials dialog */
        dwError = ERROR_ELEVATION_REQUIRED;
        goto done;
    }

    dwError = OpenElevationImage(hBinding, pRequest->ApplicationName, pRequest->CommandLine,
                                 pRequest->CurrentDirectory, &hImage, FinalPath, _countof(FinalPath));
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* The broker holds SeTcbPrivilege, so this is the primary elevated token; a
     * credentials prompt brings its own logon instead */
    if (!Credentials)
    {
        if (!GetTokenInformation(hCallerToken, TokenLinkedToken, &Linked, sizeof(Linked), &Length) ||
            Linked.LinkedToken == NULL)
        {
            ERR("The caller's logon has no elevated token: Error %lu\n", GetLastError());
            dwError = ERROR_ELEVATION_REQUIRED;
            goto done;
        }
        hElevated = Linked.LinkedToken;
    }

    if (Policy != 0 || Credentials)
    {
        DWORD OwnerPid = 0;

        Prompt = BeginPrompt(CallerPid, &LogonId);
        if (Prompt == NULL)
        {
            dwError = ERROR_BUSY;
            goto done;
        }

        /* The policy is the broker's to read; the prompt goes to the secure desktop when it says so,
         * and a secure desktop that cannot be held refuses the request (no quieter prompt instead) */
        ConsentDesktop = Desktop;
        if (ReadPolicyDword(L"PromptOnSecureDesktop", 0) != 0)
        {
            dwError = SecureDesktopBegin(SessionId, CONSENT_TIMEOUT_MS, &hSecureDesktop);
            if (dwError != ERROR_SUCCESS)
            {
                ERR("The secure desktop of session %lu could not be held: Error %lu\n", SessionId, dwError);
                dwError = ERROR_ACCESS_DENIED;
                goto done;
            }
            ConsentDesktop = SECL_SECURE_DESKTOP;
        }
        /* The caller's window can own the prompt only on the caller's desktop; on the
         * secure desktop the prompt owns itself */
        if (ConsentDesktop == Desktop &&
            pRequest->hwndOwner != 0 && IsWindow((HWND)pRequest->hwndOwner) &&
            GetWindowThreadProcessId((HWND)pRequest->hwndOwner, &OwnerPid) && OwnerPid == CallerPid)
        {
            hwndOwner = pRequest->hwndOwner;
        }
        /* A standard user types an administrator's account; a split administrator sees the own one */
        if (!IsLimited)
            Account[0] = UNICODE_NULL;
        else if (!GetTokenAccountName(hCallerToken, Account, _countof(Account)))
        {
            dwError = ERROR_ACCESS_DENIED;
            goto done;
        }
        if (Credentials)
            dwError = AskCredentials(SessionId, ConsentDesktop, Account, FinalPath, pRequest->CommandLine, hwndOwner, &hElevated, &Allowed);
        else
            dwError = AskConsent(SessionId, ConsentDesktop, Account, FinalPath, pRequest->CommandLine, hwndOwner, &Allowed);
        /* consent.exe is gone here on every path (AskConsent waits for it or ends it) */
        if (hSecureDesktop != NULL)
        {
            SecureDesktopEnd(hSecureDesktop);
            hSecureDesktop = NULL;
        }
        if (dwError != ERROR_SUCCESS)
            goto done;
        RecordRequestResult(CallerPid, &LogonId, !Allowed);
        if (!Allowed)
        {
            dwError = ERROR_CANCELLED;
            goto done;
        }
    }

    if (!SetTokenInformation(hElevated, TokenSessionId, &SessionId, sizeof(SessionId)))
    {
        dwError = GetLastError();
        goto done;
    }

    dwError = LoadProfileWhenOtherUser(hCallerToken, hElevated, ProfileUser, _countof(ProfileUser), &ProfileInfo);
    if (dwError != ERROR_SUCCESS)
    {
        ERR("The profile of the elevated account could not be loaded: Error %lu\n", dwError);
        goto done;
    }

    if (pRequest->dwDesktopInherited && SameSession)
    {
        Grant = GrantDesktopAccess(hBinding, hElevated, Desktop, &dwError);
        dwError = ERROR_SUCCESS;
    }

    if (!CreateEnvironmentBlock(&Environment, hElevated, FALSE))
    {
        dwError = GetLastError();
        goto done;
    }

    if (pRequest->CommandLine != NULL)
    {
        Length = (DWORD)wcslen(pRequest->CommandLine) + 1;
        CommandLine = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
        if (CommandLine == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }
        CopyMemory(CommandLine, pRequest->CommandLine, Length * sizeof(WCHAR));
    }

    StartupInfo.lpDesktop = (LPWSTR)Desktop;
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = (WORD)pRequest->dwShowCmd;
    if (!CreateProcessAsUserW(hElevated,
                              FinalPath,
                              CommandLine,
                              NULL,
                              NULL,
                              FALSE,
                              (pRequest->dwCreationFlags & SECL_ALLOWED_CREATION_FLAGS) | CREATE_UNICODE_ENVIRONMENT,
                              Environment,
                              pRequest->CurrentDirectory,
                              &StartupInfo,
                              &ProcessInfo))
    {
        dwError = GetLastError();
        WARN("CreateProcessAsUser(elevated) failed with Error %lu\n", dwError);
        goto done;
    }

    if (Grant && WatchDesktopGrant(Grant, ProcessInfo.hProcess))
        Grant = NULL;

    /* The caller may wait for and query the process, nothing more */
    if (!DuplicateHandle(GetCurrentProcess(), ProcessInfo.hProcess, hCallerProcess,
                         (PHANDLE)&pResponse->hProcess, SECL_ELEVATED_PROCESS_ACCESS, FALSE, 0))
    {
        pResponse->hProcess = 0;
    }
    pResponse->hThread = 0;
    pResponse->dwProcessId = ProcessInfo.dwProcessId;
    pResponse->dwThreadId = ProcessInfo.dwThreadId;
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

done:
    if (hSecureDesktop != NULL)
        SecureDesktopEnd(hSecureDesktop);
    if (dwError != ERROR_SUCCESS)
        ERR("Elevation request of process %lu (session %lu, policy %lu) ends with Error %lu\n", CallerPid, SessionId, Policy, dwError);
    if (hImage != NULL)
        CloseHandle(hImage);
    if (CommandLine != NULL)
        HeapFree(GetProcessHeap(), 0, CommandLine);
    if (Environment != NULL)
        DestroyEnvironmentBlock(Environment);
    if (Grant != NULL)
        ReleaseDesktopGrant(Grant);
    if (Prompt != NULL)
        EndPrompt(Prompt);
    if (ProfileInfo.hProfile != NULL)
        UnloadUserProfile(hElevated, ProfileInfo.hProfile);
    if (hElevated != NULL && hElevated != Linked.LinkedToken)
        CloseHandle(hElevated);
    if (Linked.LinkedToken != NULL)
        CloseHandle(Linked.LinkedToken);
    if (hCallerToken != NULL)
        CloseHandle(hCallerToken);
    if (hCallerProcess != NULL)
        CloseHandle(hCallerProcess);
    pResponse->dwError = dwError;
}

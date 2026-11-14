/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test GetNamedPipeClientComputerNameA/W on local pipe clients
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "precomp.h"
#include <ndk/iofuncs.h>

#define PIPE_NAME L"\\\\.\\pipe\\libernt_apitest_client_computer_name"

typedef BOOL (WINAPI *FN_GetNamedPipeClientComputerNameW)(HANDLE, LPWSTR, ULONG);
typedef BOOL (WINAPI *FN_GetNamedPipeClientComputerNameA)(HANDLE, LPSTR, ULONG);

typedef struct _TEST_PIPE_CLIENT_PROCESS_BUFFER_EX
{
    PVOID ClientSession;
    PVOID ClientProcess;
    USHORT ClientComputerNameLength;
    WCHAR ClientComputerBuffer[16];
} TEST_PIPE_CLIENT_PROCESS_BUFFER_EX;

static FN_GetNamedPipeClientComputerNameW pGetNameW;
static FN_GetNamedPipeClientComputerNameA pGetNameA;

static
VOID
ExpectLocal(
    _In_ HANDLE Pipe,
    _In_ PCSTR What)
{
    WCHAR NameW[32];
    CHAR NameA[32];
    BOOL Result;

    SetLastError(0xdeadbeef);
    Result = pGetNameW(Pipe, NameW, sizeof(NameW));
    ok(Result == FALSE, "%s: GetNamedPipeClientComputerNameW succeeded\n", What);
    ok(GetLastError() == ERROR_PIPE_LOCAL, "%s: W last error %lu\n", What, GetLastError());

    SetLastError(0xdeadbeef);
    Result = pGetNameA(Pipe, NameA, sizeof(NameA));
    ok(Result == FALSE, "%s: GetNamedPipeClientComputerNameA succeeded\n", What);
    ok(GetLastError() == ERROR_PIPE_LOCAL, "%s: A last error %lu\n", What, GetLastError());
}

static
VOID
TestLocalClient(VOID)
{
    TEST_PIPE_CLIENT_PROCESS_BUFFER_EX Forged;
    IO_STATUS_BLOCK Iosb;
    HANDLE Server, Client;
    NTSTATUS Status;
    BOOL Connected;

    Server = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                              1, 512, 512, 0, NULL);
    ok(Server != INVALID_HANDLE_VALUE, "CreateNamedPipeW failed with %lu\n", GetLastError());
    if (Server == INVALID_HANDLE_VALUE)
        return;

    Client = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(Client != INVALID_HANDLE_VALUE, "CreateFileW failed with %lu\n", GetLastError());
    if (Client == INVALID_HANDLE_VALUE)
    {
        CloseHandle(Server);
        return;
    }

    Connected = ConnectNamedPipe(Server, NULL);
    ok(Connected || GetLastError() == ERROR_PIPE_CONNECTED, "ConnectNamedPipe failed with %lu\n", GetLastError());

    ExpectLocal(Server, "server end");

    RtlZeroMemory(&Forged, sizeof(Forged));
    Status = NtFsControlFile(Server, NULL, NULL, NULL, &Iosb, FSCTL_PIPE_QUERY_CLIENT_PROCESS,
                             NULL, 0, &Forged, 2 * sizeof(PVOID) - 1);
    ok(Status == STATUS_INVALID_PARAMETER, "FSCTL_PIPE_QUERY_CLIENT_PROCESS with a short buffer returned 0x%lx\n", Status);

    RtlZeroMemory(&Forged, sizeof(Forged));
    Forged.ClientSession = (PVOID)(ULONG_PTR)0x5A5A;
    Forged.ClientProcess = (PVOID)(ULONG_PTR)0x1234;
    Forged.ClientComputerNameLength = sizeof(L"FORGED") - sizeof(WCHAR);
    RtlCopyMemory(Forged.ClientComputerBuffer, L"FORGED", sizeof(L"FORGED"));
    Status = NtFsControlFile(Server, NULL, NULL, NULL, &Iosb, FSCTL_PIPE_SET_CLIENT_PROCESS,
                             &Forged, sizeof(Forged), NULL, 0);
    ok(Status == STATUS_NOT_SUPPORTED, "FSCTL_PIPE_SET_CLIENT_PROCESS from user mode returned 0x%lx\n", Status);

    ExpectLocal(Server, "server end after a user-mode set attempt");

    CloseHandle(Client);
    DisconnectNamedPipe(Server);
    CloseHandle(Server);
}

static
VOID
TestQueryClientProcess(VOID)
{
    TEST_PIPE_CLIENT_PROCESS_BUFFER_EX Query;
    IO_STATUS_BLOCK Iosb;
    HANDLE Server, Client;
    NTSTATUS Status;
    BOOL Connected;
    PUCHAR Tail;
    ULONG i;

    Server = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                              1, 512, 512, 0, NULL);
    ok(Server != INVALID_HANDLE_VALUE, "CreateNamedPipeW failed with %lu\n", GetLastError());
    if (Server == INVALID_HANDLE_VALUE)
        return;

    Client = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(Client != INVALID_HANDLE_VALUE, "CreateFileW failed with %lu\n", GetLastError());
    if (Client == INVALID_HANDLE_VALUE)
    {
        CloseHandle(Server);
        return;
    }

    Connected = ConnectNamedPipe(Server, NULL);
    ok(Connected || GetLastError() == ERROR_PIPE_CONNECTED, "ConnectNamedPipe failed with %lu\n", GetLastError());

    RtlFillMemory(&Query, sizeof(Query), 0xAA);
    Status = NtFsControlFile(Server, NULL, NULL, NULL, &Iosb, FSCTL_PIPE_QUERY_CLIENT_PROCESS,
                             NULL, 0, &Query, sizeof(Query));
    ok(Status == STATUS_SUCCESS, "FSCTL_PIPE_QUERY_CLIENT_PROCESS returned 0x%lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        ok(Iosb.Information == sizeof(Query), "Information is %Iu\n", Iosb.Information);

        /* A local client has no computer name and no session: the first slot stays zero */
        ok(Query.ClientSession == NULL, "ClientSession is %p\n", Query.ClientSession);

        /* The client process slot carries the client process id, not a kernel pointer */
        ok(Query.ClientProcess == (PVOID)(ULONG_PTR)GetCurrentProcessId(),
           "ClientProcess is %p, expected the client pid %lu\n", Query.ClientProcess, GetCurrentProcessId());

        ok(Query.ClientComputerNameLength == 0, "ClientComputerNameLength is %u\n", Query.ClientComputerNameLength);
        Tail = (PUCHAR)&Query.ClientComputerBuffer[0];
        for (i = 0; i < sizeof(Query.ClientComputerBuffer); i++)
            ok(Tail[i] == 0, "Byte %lu of the name buffer is 0x%x\n", i, Tail[i]);
    }

    CloseHandle(Client);
    DisconnectNamedPipe(Server);
    CloseHandle(Server);
}

static
VOID
TestInvalidHandles(VOID)
{
    WCHAR Path[MAX_PATH], File[MAX_PATH];
    WCHAR NameW[32];
    CHAR NameA[32];
    HANDLE Handle;
    BOOL Result;

    SetLastError(0xdeadbeef);
    Result = pGetNameW(NULL, NameW, sizeof(NameW));
    ok(Result == FALSE, "GetNamedPipeClientComputerNameW(NULL) succeeded\n");
    ok(GetLastError() == ERROR_INVALID_HANDLE, "W last error %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    Result = pGetNameA(NULL, NameA, sizeof(NameA));
    ok(Result == FALSE, "GetNamedPipeClientComputerNameA(NULL) succeeded\n");
    ok(GetLastError() == ERROR_INVALID_HANDLE, "A last error %lu\n", GetLastError());

    GetTempPathW(RTL_NUMBER_OF(Path), Path);
    GetTempFileNameW(Path, L"pcn", 0, File);
    Handle = CreateFileW(File, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFileW(%S) failed with %lu\n", File, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        Result = pGetNameW(Handle, NameW, sizeof(NameW));
        ok(Result == FALSE, "GetNamedPipeClientComputerNameW on a disk file succeeded\n");
        ok(GetLastError() != ERROR_PIPE_LOCAL, "A disk file was reported as a local pipe\n");
        CloseHandle(Handle);
    }
}

START_TEST(NamedPipeClientComputerName)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");

    pGetNameW = (FN_GetNamedPipeClientComputerNameW)GetProcAddress(Kernel32, "GetNamedPipeClientComputerNameW");
    pGetNameA = (FN_GetNamedPipeClientComputerNameA)GetProcAddress(Kernel32, "GetNamedPipeClientComputerNameA");
    if (pGetNameW == NULL || pGetNameA == NULL)
    {
        skip("GetNamedPipeClientComputerNameA/W not exported\n");
        return;
    }

    TestLocalClient();
    TestQueryClientProcess();
    TestInvalidHandles();
}

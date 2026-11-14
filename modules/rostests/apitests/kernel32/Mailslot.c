/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GNU GPLv2 only as published by the Free Software Foundation
 * PURPOSE:         Test for mailslot (CORE-10188)
 * PROGRAMMER:      Nikita Pechenkin (n.pechenkin@mail.ru)
 */

#include "precomp.h"
#include <ndk/iofuncs.h>
#include <ndk/iotypes.h>

#define LMS TEXT("\\\\.\\mailslot\\rostest_slot")
#define MSG (0x50DA)

static DWORD dInMsg  = MSG;
static DWORD dOutMsg = 0x0;

static
VOID
WaitIoPending(
        HANDLE hThread)
{
    BOOL Pending = FALSE;
    ULONG i;

    for (i = 0; i < 100000 && GetThreadIOPendingFlag(hThread, &Pending) && !Pending; i++)
        SwitchToThread();
}

DWORD
WINAPI
MailSlotWriter(
        LPVOID lpParam)
{
    DWORD cbWritten;
    HANDLE hMailslot;

    hMailslot = CreateFile(LMS, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hMailslot != INVALID_HANDLE_VALUE, "CreateFile failed, results might not be accurate\n");
    if (hMailslot != INVALID_HANDLE_VALUE)
    {
        WaitIoPending((HANDLE)lpParam);
        ok(WriteFile(hMailslot, &dInMsg, sizeof(dInMsg), &cbWritten, (LPOVERLAPPED) NULL), "Slot write failed\n");
        CloseHandle(hMailslot);
    }
    return 0;
}

DWORD
WINAPI
MailSlotReader(
        LPVOID lpParam)
{
    HANDLE hMailslotClient;
    DWORD cbRead;
    HANDLE hThread;
    HANDLE hReader;

    hMailslotClient = CreateMailslot(LMS, 0L, MAILSLOT_WAIT_FOREVER, (LPSECURITY_ATTRIBUTES) NULL);
    ok(hMailslotClient != INVALID_HANDLE_VALUE, "CreateMailslot failed\n");
    if (hMailslotClient != INVALID_HANDLE_VALUE)
    {
        hReader = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
        hThread = CreateThread(NULL,0, MailSlotWriter, hReader, 0, NULL);
        ok(hThread != INVALID_HANDLE_VALUE, "CreateThread failed\n");
        if (hThread != INVALID_HANDLE_VALUE)
        {
            ok(ReadFile(hMailslotClient, &dOutMsg, sizeof(dOutMsg), &cbRead, NULL), "Slot read failed\n");
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        CloseHandle(hReader);
        CloseHandle(hMailslotClient);
    }
    return 0;
}

VOID
StartTestCORE10188(VOID)
{
    HANDLE  hThread;

    hThread = CreateThread(NULL,0, MailSlotReader, NULL, 0, NULL);
    ok(hThread != INVALID_HANDLE_VALUE, "CreateThread failed\n");
    if (hThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    ok(dInMsg == dOutMsg, "Transfer data failed\n");
}

static
VOID
TestSetMailslotInformationTimeout(VOID)
{
    const LARGE_INTEGER WantedTimeout = { { 0, -1 } }; /* relative 0.5s */
    FILE_MAILSLOT_QUERY_INFORMATION QueryInfo;
    FILE_MAILSLOT_SET_INFORMATION SetInfo;
    IO_STATUS_BLOCK Iosb;
    HANDLE Mailslot;
    NTSTATUS Status;

    Mailslot = CreateMailslot(LMS, 0L, MAILSLOT_WAIT_FOREVER, NULL);
    ok(Mailslot != INVALID_HANDLE_VALUE, "CreateMailslot failed\n");
    if (Mailslot == INVALID_HANDLE_VALUE)
        return;

    /* A valid timeout pointer is captured and applied */
    SetInfo.ReadTimeout = (PLARGE_INTEGER)&WantedTimeout;
    Status = NtSetInformationFile(Mailslot, &Iosb, &SetInfo, sizeof(SetInfo), FileMailslotSetInformation);
    ok(Status == STATUS_SUCCESS, "NtSetInformationFile(FileMailslotSetInformation) returned 0x%lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        Status = NtQueryInformationFile(Mailslot, &Iosb, &QueryInfo, sizeof(QueryInfo), FileMailslotQueryInformation);
        ok(Status == STATUS_SUCCESS, "NtQueryInformationFile(FileMailslotQueryInformation) returned 0x%lx\n", Status);
        if (Status == STATUS_SUCCESS)
            ok(QueryInfo.ReadTimeout.QuadPart == WantedTimeout.QuadPart,
               "ReadTimeout is %I64d, expected %I64d\n", QueryInfo.ReadTimeout.QuadPart, WantedTimeout.QuadPart);
    }

    /* A caller pointer that faults is rejected, not dereferenced in kernel mode */
    SetInfo.ReadTimeout = (PLARGE_INTEGER)(ULONG_PTR)0x7EADBEEC;
    Status = NtSetInformationFile(Mailslot, &Iosb, &SetInfo, sizeof(SetInfo), FileMailslotSetInformation);
    ok(Status == STATUS_ACCESS_VIOLATION, "NtSetInformationFile with a bad timeout pointer returned 0x%lx\n", Status);

    /* The mailslot still takes timeouts after the rejected call */
    SetInfo.ReadTimeout = (PLARGE_INTEGER)&WantedTimeout;
    Status = NtSetInformationFile(Mailslot, &Iosb, &SetInfo, sizeof(SetInfo), FileMailslotSetInformation);
    ok(Status == STATUS_SUCCESS, "NtSetInformationFile(FileMailslotSetInformation) after the fault returned 0x%lx\n", Status);

    CloseHandle(Mailslot);
}

START_TEST(MailslotRead)
{
    StartTestCORE10188();
    TestSetMailslotInformationTimeout();
}

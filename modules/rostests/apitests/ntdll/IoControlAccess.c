/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The access class of a control code is checked against the handle
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

/* A file opened for reading only: a read-write control code is refused by the
 * I/O manager before the file system sees it, a read code is not */
START_TEST(IoControlAccess)
{
    WCHAR Path[MAX_PATH], Name[MAX_PATH];
    HANDLE ReadOnly, ReadWrite;
    IO_STATUS_BLOCK IoStatus;
    USHORT Compression;
    NTSTATUS Status;

    if (!GetTempPathW(MAX_PATH, Path) || !GetTempFileNameW(Path, L"ioc", 0, Name))
    {
        skip("No temporary file (%lu)\n", GetLastError());
        return;
    }

    ReadOnly = CreateFileW(Name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(ReadOnly != INVALID_HANDLE_VALUE, "Read-only open failed (%lu)\n", GetLastError());
    ReadWrite = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(ReadWrite != INVALID_HANDLE_VALUE, "Read-write open failed (%lu)\n", GetLastError());
    if (ReadOnly == INVALID_HANDLE_VALUE || ReadWrite == INVALID_HANDLE_VALUE)
    {
        if (ReadOnly != INVALID_HANDLE_VALUE) CloseHandle(ReadOnly);
        if (ReadWrite != INVALID_HANDLE_VALUE) CloseHandle(ReadWrite);
        DeleteFileW(Name);
        return;
    }

    /* FSCTL_SET_COMPRESSION carries FILE_READ_DATA | FILE_WRITE_DATA */
    Compression = COMPRESSION_FORMAT_NONE;
    Status = NtFsControlFile(ReadOnly, NULL, NULL, NULL, &IoStatus, FSCTL_SET_COMPRESSION,
                             &Compression, sizeof(Compression), NULL, 0);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);

    /* The same code on a handle with both rights reaches the file system */
    Status = NtFsControlFile(ReadWrite, NULL, NULL, NULL, &IoStatus, FSCTL_SET_COMPRESSION,
                             &Compression, sizeof(Compression), NULL, 0);
    ok(Status != STATUS_ACCESS_DENIED, "Read-write handle refused: 0x%lx\n", Status);

    /* FSCTL_GET_COMPRESSION carries FILE_ANY_ACCESS */
    Compression = 0xCCCC;
    Status = NtFsControlFile(ReadOnly, NULL, NULL, NULL, &IoStatus, FSCTL_GET_COMPRESSION,
                             NULL, 0, &Compression, sizeof(Compression));
    ok(Status != STATUS_ACCESS_DENIED, "Read-only handle refused a read query: 0x%lx\n", Status);

    /* A device control with a write class on a read-only handle is refused the same way */
    Status = NtDeviceIoControlFile(ReadOnly, NULL, NULL, NULL, &IoStatus,
                                   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS),
                                   NULL, 0, NULL, 0);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);

    CloseHandle(ReadOnly);
    CloseHandle(ReadWrite);
    DeleteFileW(Name);
}

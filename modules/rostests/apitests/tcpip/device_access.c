/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Who may change the IP stack through its control devices
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <winioctl.h>
#include <tcpioctl.h>
#include <tcpip_undoc.h>
#include <tdiinfo.h>

static
HANDLE
OpenDevice(
    _In_ PCWSTR Name,
    _In_ DWORD Access)
{
    return CreateFileW(Name, Access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

/* The write-class codes are refused on a handle without write access, before the driver looks at the data */
static
VOID
TestWriteCodesOnReadHandle(
    _In_ HANDLE Device)
{
    UCHAR Buffer[64];
    DWORD Returned = 0;
    BOOL Result;
    DWORD Error;

    RtlZeroMemory(Buffer, sizeof(Buffer));

    Result = DeviceIoControl(Device, IOCTL_IP_SET_ROUTE, Buffer, sizeof(Buffer), NULL, 0, &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(!Result && Error == ERROR_ACCESS_DENIED, "IP_SET_ROUTE on a read handle: result %d, error %lu\n", Result, Error);

    Result = DeviceIoControl(Device, IOCTL_IP_SET_ADDRESS, Buffer, sizeof(Buffer), NULL, 0, &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(!Result && Error == ERROR_ACCESS_DENIED, "IP_SET_ADDRESS on a read handle: result %d, error %lu\n", Result, Error);

    Result = DeviceIoControl(Device, IOCTL_IP_FLUSH_PATHS, NULL, 0, NULL, 0, &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(!Result && Error == ERROR_ACCESS_DENIED, "IP_FLUSH_PATHS on a read handle: result %d, error %lu\n", Result, Error);

    /* A query is not an access matter on the same handle */
    Result = DeviceIoControl(Device, IOCTL_IP_QUERY_ROUTE, Buffer, sizeof(Buffer), Buffer, sizeof(Buffer), &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(Error != ERROR_ACCESS_DENIED, "IP_QUERY_ROUTE on a read handle: access denied\n");
}

/* Without the administrators group the devices open for reading only */
static
VOID
TestRestrictedOpens(VOID)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    HANDLE Token = NULL, Restricted = NULL, Device;
    SID_AND_ATTRIBUTES Disable;
    PSID Admins = NULL;
    DWORD Error;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &Admins))
    {
        skip("No administrators SID (%lu)\n", GetLastError());
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &Token))
    {
        skip("No process token (%lu)\n", GetLastError());
        FreeSid(Admins);
        return;
    }
    Disable.Sid = Admins;
    Disable.Attributes = 0;
    if (!CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE, 1, &Disable, 0, NULL, 0, NULL, &Restricted))
    {
        skip("No restricted token (%lu)\n", GetLastError());
        CloseHandle(Token);
        FreeSid(Admins);
        return;
    }
    if (!ImpersonateLoggedOnUser(Restricted))
    {
        skip("Cannot impersonate the restricted token (%lu)\n", GetLastError());
        CloseHandle(Restricted);
        CloseHandle(Token);
        FreeSid(Admins);
        return;
    }

    Device = OpenDevice(L"\\\\.\\Ip", GENERIC_READ);
    ok(Device != INVALID_HANDLE_VALUE, "Restricted: IP device for reading failed with %lu\n", GetLastError());
    if (Device != INVALID_HANDLE_VALUE)
        CloseHandle(Device);

    Device = OpenDevice(L"\\\\.\\Ip", GENERIC_WRITE);
    Error = Device == INVALID_HANDLE_VALUE ? GetLastError() : NO_ERROR;
    ok(Device == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED,
       "Restricted: IP device for writing: error %lu\n", Error);
    if (Device != INVALID_HANDLE_VALUE)
        CloseHandle(Device);

    Device = OpenDevice(L"\\\\.\\Ip6", GENERIC_WRITE);
    Error = Device == INVALID_HANDLE_VALUE ? GetLastError() : NO_ERROR;
    ok(Device == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED,
       "Restricted: IPv6 device for writing: error %lu\n", Error);
    if (Device != INVALID_HANDLE_VALUE)
        CloseHandle(Device);

    Device = OpenDevice(L"\\\\.\\Tcp", GENERIC_WRITE);
    Error = Device == INVALID_HANDLE_VALUE ? GetLastError() : NO_ERROR;
    ok(Device == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED,
       "Restricted: TCP device for writing: error %lu\n", Error);
    if (Device != INVALID_HANDLE_VALUE)
        CloseHandle(Device);

    RevertToSelf();
    CloseHandle(Restricted);
    CloseHandle(Token);
    FreeSid(Admins);
}

START_TEST(device_access)
{
    HANDLE Device;

    Device = OpenDevice(L"\\\\.\\Ip", GENERIC_READ);
    if (Device == INVALID_HANDLE_VALUE)
    {
        skip("The IP device cannot be opened for reading (error %lu)\n", GetLastError());
        return;
    }
    TestWriteCodesOnReadHandle(Device);
    CloseHandle(Device);

    TestRestrictedOpens();
}

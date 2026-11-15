/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Who may change the IP stack through its control devices
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <winioctl.h>
#include <tcpioctl.h>
#include <tcpip_undoc.h>
#include <tdiinfo.h>

/* The stack's devices have no DOS names; iphlpapi, nsi.dll and the DHCP client open them by their NT names */
static const WCHAR IpDevice[] = L"\\Device\\Ip";
static const WCHAR Ip6Device[] = L"\\Device\\Ip6";
static const WCHAR TcpDevice[] = L"\\Device\\Tcp";

static
NTSTATUS
OpenDevice(
    _In_ PCWSTR Name,
    _In_ ACCESS_MASK Access,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING DeviceName;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    *Handle = NULL;
    RtlInitUnicodeString(&DeviceName, Name);
    InitializeObjectAttributes(&Attributes, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenFile(Handle, Access | SYNCHRONIZE, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_SYNCHRONOUS_IO_NONALERT);
}

static
BOOL
IsAdministrator(VOID)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Admins;
    BOOL Member = FALSE;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &Admins))
        return FALSE;
    if (!CheckTokenMembership(NULL, Admins, &Member))
        Member = FALSE;
    FreeSid(Admins);
    return Member;
}

/* The write-class codes are refused by the I/O manager on a handle without write access, before the driver looks
 * at the data */
static
VOID
TestWriteCodesOnReadHandle(VOID)
{
    UCHAR Buffer[64];
    HANDLE Device;
    NTSTATUS Status;
    DWORD Returned = 0;
    BOOL Result;
    DWORD Error;

    Status = OpenDevice(IpDevice, FILE_READ_DATA, &Device);
    ok(NT_SUCCESS(Status), "IP device for reading: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

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

    NtClose(Device);
}

/* An administrator's handle opened for writing reaches the set codes: the driver answers the request itself (an
 * interface or context that does not exist), never with access denied. This is the path the DHCP client and
 * iphlpapi take; a device open sets no access flags on the file object, so the driver cannot judge this itself. */
static
VOID
TestWriteCodesOnWriteHandle(VOID)
{
    /* The address request of the TCP device, as iphlpapi lays it out */
    struct
    {
        ULONG NteContext;
        ULONG NewAddress;
        ULONG NewNetmask;
    } Address;
    IP4_INTERFACE_INFO Interface;
    HANDLE Device;
    NTSTATUS Status;
    DWORD Returned = 0;
    DWORD Error;
    BOOL Result;

    Status = OpenDevice(IpDevice, FILE_WRITE_DATA, &Device);
    if (!NT_SUCCESS(Status))
    {
        if (IsAdministrator())
        {
            ok(FALSE, "Administrator: IP device for writing failed with 0x%lx\n", Status);
        }
        else
        {
            /* The refusal is the expected answer for a standard user */
            ok(Status == STATUS_ACCESS_DENIED, "Standard user: IP device for writing: 0x%lx\n", Status);
            skip("Not an administrator: the write handle cases need one\n");
        }
        return;
    }
    ok(IsAdministrator(), "Standard user: the IP device opened for writing\n");

    RtlZeroMemory(&Interface, sizeof(Interface));
    Interface.Index = 0xFFFFFFFF;
    Result = DeviceIoControl(Device, IOCTL_IP_SET_INTERFACE, &Interface, sizeof(Interface), NULL, 0, &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(Error != ERROR_ACCESS_DENIED, "IP_SET_INTERFACE on a write handle: access denied\n");
    NtClose(Device);

    /* iphlpapi opens the TCP device this way to add and delete addresses */
    Status = OpenDevice(TcpDevice, FILE_READ_DATA | FILE_WRITE_DATA, &Device);
    ok(NT_SUCCESS(Status), "TCP device for reading and writing: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(&Address, sizeof(Address));
    Address.NteContext = 0xFFFFFFFF;
    Result = DeviceIoControl(Device, IOCTL_SET_IP_ADDRESS, &Address, sizeof(Address), &Address, sizeof(Address),
                             &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(Error != ERROR_ACCESS_DENIED, "SET_IP_ADDRESS on a write handle: access denied\n");
    ok(!Result, "SET_IP_ADDRESS for an unknown context succeeded\n");
    NtClose(Device);
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
    NTSTATUS Status;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &Admins))
    {
        ok(FALSE, "No administrators SID (%lu)\n", GetLastError());
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &Token))
    {
        ok(FALSE, "No process token (%lu)\n", GetLastError());
        FreeSid(Admins);
        return;
    }
    Disable.Sid = Admins;
    Disable.Attributes = 0;
    if (!CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE, 1, &Disable, 0, NULL, 0, NULL, &Restricted))
    {
        ok(FALSE, "No restricted token (%lu)\n", GetLastError());
        CloseHandle(Token);
        FreeSid(Admins);
        return;
    }
    if (!ImpersonateLoggedOnUser(Restricted))
    {
        ok(FALSE, "Cannot impersonate the restricted token (%lu)\n", GetLastError());
        CloseHandle(Restricted);
        CloseHandle(Token);
        FreeSid(Admins);
        return;
    }

    Status = OpenDevice(IpDevice, FILE_READ_DATA, &Device);
    ok(NT_SUCCESS(Status), "Restricted: IP device for reading: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Device);

    Status = OpenDevice(IpDevice, FILE_WRITE_DATA, &Device);
    ok(Status == STATUS_ACCESS_DENIED, "Restricted: IP device for writing: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Device);

    Status = OpenDevice(Ip6Device, FILE_WRITE_DATA, &Device);
    ok(Status == STATUS_ACCESS_DENIED, "Restricted: IPv6 device for writing: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Device);

    Status = OpenDevice(TcpDevice, FILE_WRITE_DATA, &Device);
    ok(Status == STATUS_ACCESS_DENIED, "Restricted: TCP device for writing: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Device);

    RevertToSelf();
    CloseHandle(Restricted);
    CloseHandle(Token);
    FreeSid(Admins);
}

START_TEST(device_access)
{
    TestWriteCodesOnReadHandle();
    TestWriteCodesOnWriteHandle();
    TestRestrictedOpens();
}

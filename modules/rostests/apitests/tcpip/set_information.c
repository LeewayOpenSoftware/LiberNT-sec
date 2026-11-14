/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     TCP_SET_INFORMATION_EX refuses an entity of the wrong kind
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <winioctl.h>
#include <tcpioctl.h>
#include <tcpip_undoc.h>
#include <tdiinfo.h>

/* The request carries a one-byte option value */
typedef struct _SET_REQUEST
{
    TCP_REQUEST_SET_INFORMATION_EX Req;
    UCHAR Pad[16];
} SET_REQUEST;

static
VOID
ExpectInvalid(
    _In_ HANDLE Tcp,
    _In_ ULONG Entity,
    _In_ ULONG Instance,
    _In_ ULONG Type,
    _In_ ULONG Id,
    _In_ PCSTR What)
{
    SET_REQUEST Request;
    DWORD Returned = 0;
    BOOL Result;
    DWORD Error;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.Req.ID.toi_entity.tei_entity = Entity;
    Request.Req.ID.toi_entity.tei_instance = Instance;
    Request.Req.ID.toi_class = INFO_CLASS_PROTOCOL;
    Request.Req.ID.toi_type = Type;
    Request.Req.ID.toi_id = Id;
    Request.Req.BufferSize = sizeof(ULONG);
    Request.Req.Buffer[0] = 1;

    Result = DeviceIoControl(Tcp, IOCTL_TCP_SET_INFORMATION_EX, &Request, sizeof(Request), NULL, 0, &Returned, NULL);
    Error = Result ? NO_ERROR : GetLastError();
    ok(!Result && Error == ERROR_INVALID_PARAMETER, "%s: result %d, error %lu\n", What, Result, Error);
}

START_TEST(set_information)
{
    HANDLE Tcp;

    Tcp = CreateFileW(L"\\\\.\\Tcp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
    if (Tcp == INVALID_HANDLE_VALUE)
    {
        skip("The TCP device cannot be opened for writing (error %lu); this needs an administrator\n", GetLastError());
        return;
    }

    /* A connection option on entities that are interfaces, not address files */
    ExpectInvalid(Tcp, IF_ENTITY, 0, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on an interface entity");
    ExpectInvalid(Tcp, AT_ENTITY, 0, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on an ARP entity");
    ExpectInvalid(Tcp, CL_NL_ENTITY, 0, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on an IP entity");

    /* A connection option on address files without connections */
    ExpectInvalid(Tcp, CL_TL_ENTITY, 0, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on a UDP entity");
    ExpectInvalid(Tcp, ER_ENTITY, 0, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on an ICMP entity");

    /* An address object option on an interface entity */
    ExpectInvalid(Tcp, IF_ENTITY, 0, INFO_TYPE_ADDRESS_OBJECT, AO_OPTION_TTL, "address option on an interface entity");
    ExpectInvalid(Tcp, CL_NL_ENTITY, 0, INFO_TYPE_ADDRESS_OBJECT, AO_OPTION_TTL, "address option on an IP entity");

    /* A TCP entity instance that does not exist */
    ExpectInvalid(Tcp, CO_TL_ENTITY, 0x7FFFFFFF, INFO_TYPE_CONNECTION, TCP_SOCKET_NODELAY, "connection option on a missing TCP entity");

    CloseHandle(Tcp);
}

/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Regression probes for the AFD request hardening: accepting on a
 *              foreign handle, NULL send buffers, and truncated request lengths
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

static
void
SetupListeningPair(
    _Out_ PHANDLE Listener,
    _Out_ PHANDLE Client,
    _Out_ PULONG SequenceNumber)
{
    NTSTATUS Status;
    HANDLE Server = NULL, Peer = NULL;
    IO_STATUS_BLOCK IoStatus;
    AFD_LISTEN_DATA ListenData;
    UCHAR WaitBuffer[FIELD_OFFSET(AFD_RECEIVED_ACCEPT_DATA, Address) + sizeof(TA_IP_ADDRESS)];
    PAFD_RECEIVED_ACCEPT_DATA Received = (PAFD_RECEIVED_ACCEPT_DATA)WaitBuffer;
    struct sockaddr_in Addr;
    INT NameLength = sizeof(Addr);

    RtlZeroMemory(&ListenData, sizeof(ListenData));
    RtlZeroMemory(WaitBuffer, sizeof(WaitBuffer));

    Status = AfdCreateSocket(&Server, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket(listener) failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    RtlZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    Addr.sin_port = 0;
    Status = AfdBind(Server, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdBind(listener) failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    ListenData.Backlog = 4;
    Status = NtDeviceIoControlFile(Server,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_LISTEN,
                                   &ListenData,
                                   sizeof(ListenData),
                                   NULL,
                                   0);
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Server, FALSE, NULL);
        Status = IoStatus.Status;
    }
    ok(Status == STATUS_SUCCESS, "IOCTL_AFD_LISTEN failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = AfdCreateSocket(&Peer, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket(client) failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    /* ask the stack for the port the listener got */
    Status = AfdGetSockName(Server, (struct sockaddr *)&Addr, &NameLength);
    ok(Status == STATUS_SUCCESS, "AfdGetSockName failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = AfdConnect(Peer, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdConnect(client) failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = NtDeviceIoControlFile(Server,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_WAIT_FOR_LISTEN,
                                   NULL,
                                   0,
                                   WaitBuffer,
                                   sizeof(WaitBuffer));
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Server, FALSE, NULL);
        Status = IoStatus.Status;
    }
    ok(Status == STATUS_SUCCESS, "IOCTL_AFD_WAIT_FOR_LISTEN failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    *SequenceNumber = Received->SequenceNumber;
    *Listener = Server;
    *Client = Peer;
    return;

Cleanup:
    if (Server) NtClose(Server);
    if (Peer) NtClose(Peer);
    *Listener = NULL;
    *Client = NULL;
}

static
void
TestAcceptForeignHandle(void)
{
    NTSTATUS Status;
    HANDLE Listener = NULL, Client = NULL, Target = NULL;
    HANDLE Foreign = NULL;
    IO_STATUS_BLOCK IoStatus;
    ULONG SequenceNumber;
    AFD_ACCEPT_DATA AcceptData;
    WCHAR TempPath[MAX_PATH];
    CHAR FileBuffer[8];

    /* a real socket handle must keep working */
    SetupListeningPair(&Listener, &Client, &SequenceNumber);
    if (!Listener)
        return;

    Status = AfdCreateSocket(&Target, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket(target) failed with %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(&AcceptData, sizeof(AcceptData));
        AcceptData.SequenceNumber = SequenceNumber;
        AcceptData.ListenHandle = Target;
        Status = NtDeviceIoControlFile(Listener,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &IoStatus,
                                       IOCTL_AFD_ACCEPT,
                                       &AcceptData,
                                       sizeof(AcceptData),
                                       NULL,
                                       0);
        ok(Status == STATUS_SUCCESS, "accept on an AFD socket failed with %lx\n", Status);
        NtClose(Target);
    }
    NtClose(Client);
    NtClose(Listener);

    /* the foreign handles must be refused, not used as a socket */
    Listener = Client = NULL;
    SetupListeningPair(&Listener, &Client, &SequenceNumber);
    if (Listener)
    {
        Foreign = CreateEventW(NULL, FALSE, FALSE, NULL);
        ok(Foreign != NULL, "CreateEvent failed with %lu\n", GetLastError());
        if (Foreign)
        {
            RtlZeroMemory(&AcceptData, sizeof(AcceptData));
            AcceptData.SequenceNumber = SequenceNumber;
            AcceptData.ListenHandle = Foreign;
            Status = NtDeviceIoControlFile(Listener,
                                           NULL,
                                           NULL,
                                           NULL,
                                           &IoStatus,
                                           IOCTL_AFD_ACCEPT,
                                           &AcceptData,
                                           sizeof(AcceptData),
                                           NULL,
                                           0);
            ok(!NT_SUCCESS(Status), "accept on an event handle succeeded with %lx\n", Status);
            NtClose(Foreign);
        }

        if (GetTempPathW(RTL_NUMBER_OF(TempPath), TempPath))
        {
            Foreign = CreateFileW(TempPath,
                                  GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS,
                                  NULL);
            ok(Foreign != INVALID_HANDLE_VALUE, "CreateFile(%S) failed with %lu\n",
               TempPath, GetLastError());
            if (Foreign != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(&AcceptData, sizeof(AcceptData));
                AcceptData.SequenceNumber = SequenceNumber;
                AcceptData.ListenHandle = Foreign;
                Status = NtDeviceIoControlFile(Listener,
                                               NULL,
                                               NULL,
                                               NULL,
                                               &IoStatus,
                                               IOCTL_AFD_ACCEPT,
                                               &AcceptData,
                                               sizeof(AcceptData),
                                               NULL,
                                               0);
                ok(!NT_SUCCESS(Status), "accept on a directory handle succeeded with %lx\n", Status);
                RtlZeroMemory(FileBuffer, sizeof(FileBuffer));
                ok(ReadFile(Foreign, FileBuffer, sizeof(FileBuffer), NULL, NULL) == FALSE,
                   "the directory handle was tampered with\n");
                NtClose(Foreign);
            }
        }

        /* a kernel-range handle value must not pass for a user caller */
        RtlZeroMemory(&AcceptData, sizeof(AcceptData));
        AcceptData.SequenceNumber = SequenceNumber;
        AcceptData.ListenHandle = (HANDLE)(ULONG_PTR)0xFFFFFFFF;
        Status = NtDeviceIoControlFile(Listener,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &IoStatus,
                                       IOCTL_AFD_ACCEPT,
                                       &AcceptData,
                                       sizeof(AcceptData),
                                       NULL,
                                       0);
        ok(!NT_SUCCESS(Status), "accept on a kernel handle value succeeded with %lx\n", Status);
    }

    if (Listener) NtClose(Listener);
    if (Client) NtClose(Client);
}

static
void
TestNullBufferSend(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    AFD_SEND_INFO SendInfo;
    AFD_WSABUF AfdBuffer;
    struct sockaddr_in Addr;

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    Addr.sin_port = 0;
    Status = AfdBind(SocketHandle, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdBind failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        NtClose(SocketHandle);
        return;
    }

    AfdBuffer.buf = NULL;
    AfdBuffer.len = 16;
    SendInfo.BufferArray = &AfdBuffer;
    SendInfo.BufferCount = 1;
    SendInfo.TdiFlags = 0;
    SendInfo.AfdFlags = 0;

    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_SEND,
                                   &SendInfo,
                                   sizeof(SendInfo),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "send with a NULL buffer and a length succeeded with %lx\n", Status);

    NtClose(SocketHandle);
}

static
void
TestMinimumLengths(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    UCHAR ShortBuffer[16];
    AFD_INFO InfoData;
    AFD_LISTEN_DATA ListenData;
    struct sockaddr_in Addr;

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    Addr.sin_port = 0;
    Status = AfdBind(SocketHandle, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdBind failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        NtClose(SocketHandle);
        return;
    }

    RtlZeroMemory(ShortBuffer, sizeof(ShortBuffer));

    /* AFD_INFO needs the class and the value: 16 bytes, 8 must fail */
    RtlZeroMemory(&InfoData, sizeof(InfoData));
    InfoData.InformationClass = AFD_INFO_SEND_WINDOW_SIZE;
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_SET_INFO,
                                   &InfoData,
                                   FIELD_OFFSET(AFD_INFO, Information),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "SET_INFO with a short request succeeded with %lx\n", Status);

    RtlZeroMemory(&InfoData, sizeof(InfoData));
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_GET_INFO,
                                   &InfoData,
                                   FIELD_OFFSET(AFD_INFO, Information),
                                   &InfoData,
                                   sizeof(InfoData));
    ok(!NT_SUCCESS(Status), "GET_INFO with a short request succeeded with %lx\n", Status);

    /* AFD_DISCONNECT_INFO needs the type: 4 bytes, 2 must fail */
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_DISCONNECT,
                                   ShortBuffer,
                                   sizeof(USHORT),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "DISCONNECT with a 2-byte request succeeded with %lx\n", Status);

    /* AFD_LISTEN_DATA needs the full data: 12 bytes, 4 must fail */
    RtlZeroMemory(&ListenData, sizeof(ListenData));
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_LISTEN,
                                   &ListenData,
                                   sizeof(ULONG),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "LISTEN with a 4-byte request succeeded with %lx\n", Status);

    /* AFD_BIND_DATA needs the inline address after the share type */
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_BIND,
                                   ShortBuffer,
                                   FIELD_OFFSET(AFD_BIND_DATA, Address),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "BIND without an address succeeded with %lx\n", Status);

    /* an address whose count runs past the request must fail */
    {
        struct
        {
            ULONG ShareType;
            TRANSPORT_ADDRESS Address;
        } BindRequest;
        RtlZeroMemory(&BindRequest, sizeof(BindRequest));
        BindRequest.Address.TAAddressCount = 1;
        Status = NtDeviceIoControlFile(SocketHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &IoStatus,
                                       IOCTL_AFD_BIND,
                                       &BindRequest,
                                       FIELD_OFFSET(AFD_BIND_DATA, Address) + sizeof(USHORT),
                                       NULL,
                                       0);
        ok(!NT_SUCCESS(Status), "BIND with a truncated address succeeded with %lx\n", Status);
    }

    /* AFD_CONNECT_INFO needs the inline remote address */
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_CONNECT,
                                   ShortBuffer,
                                   FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "CONNECT without an address succeeded with %lx\n", Status);

    NtClose(SocketHandle);
}

static
void
TestSelect(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    UCHAR Buffer[sizeof(AFD_POLL_INFO) + sizeof(AFD_HANDLE)];

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    /* every handle in the array must be referenced for the caller's mode:
     * a request for an access the caller does not hold must not fail */
    RtlZeroMemory(Buffer, sizeof(Buffer));
    ((PAFD_POLL_INFO)Buffer)->Timeout.QuadPart = 0;
    ((PAFD_POLL_INFO)Buffer)->HandleCount = 1;
    ((PAFD_POLL_INFO)Buffer)->Handles[0].Handle = (HANDLE)SocketHandle;
    ((PAFD_POLL_INFO)Buffer)->Handles[0].Events = AFD_EVENT_SEND;

    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_SELECT,
                                   Buffer,
                                   sizeof(Buffer),
                                   Buffer,
                                   sizeof(Buffer));
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(SocketHandle, FALSE, NULL);
        Status = IoStatus.Status;
    }
    ok(Status == STATUS_SUCCESS, "select on a socket handle failed with %lx\n", Status);

    NtClose(SocketHandle);
}

static
void
TestConnect(void)
{
    HANDLE Listener = NULL, Client = NULL;
    ULONG SequenceNumber;

    /* a normal loopback connect must keep working: it exercises the
     * transport-address fit check end to end */
    SetupListeningPair(&Listener, &Client, &SequenceNumber);
    ok(Listener != NULL, "loopback connect through the fit check failed\n");
    if (Listener) NtClose(Listener);
    if (Client) NtClose(Client);
}

static
void
TestShortAddress(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    UCHAR Buffer[sizeof(AFD_SEND_INFO_UDP)];
    AFD_SEND_INFO_UDP SendInfo;
    AFD_WSABUF AfdBuffer;
    UCHAR Payload[4];
    struct sockaddr_in Addr;
    /* an address that stops right after the count and the entry header */
    UCHAR ShortAddress[FIELD_OFFSET(TRANSPORT_ADDRESS, Address) +
                       FIELD_OFFSET(TA_ADDRESS, Address)];

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    Addr.sin_port = 0;
    Status = AfdBind(SocketHandle, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdBind failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        NtClose(SocketHandle);
        return;
    }

    RtlZeroMemory(&SendInfo, sizeof(SendInfo));
    RtlZeroMemory(ShortAddress, sizeof(ShortAddress));
    ((PTRANSPORT_ADDRESS)ShortAddress)->TAAddressCount = 1;
    ((PTRANSPORT_ADDRESS)ShortAddress)->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    ((PTRANSPORT_ADDRESS)ShortAddress)->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;

    AfdBuffer.buf = (PCHAR)Payload;
    AfdBuffer.len = sizeof(Payload);
    SendInfo.BufferArray = &AfdBuffer;
    SendInfo.BufferCount = 1;
    SendInfo.TdiFlags = 0;
    SendInfo.AfdFlags = 0;
    SendInfo.TdiConnection.RemoteAddress = (PVOID)ShortAddress;
    SendInfo.TdiConnection.RemoteAddressLength = sizeof(ShortAddress);

    RtlCopyMemory(Buffer, &SendInfo, sizeof(SendInfo));
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_SEND_DATAGRAM,
                                   Buffer,
                                   sizeof(Buffer),
                                   NULL,
                                   0);
    ok(!NT_SUCCESS(Status), "sendto with an address that ends at its header succeeded with %lx\n",
       Status);

    NtClose(SocketHandle);
}

static
void
TestCountZeroBind(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    struct
    {
        ULONG ShareType;
        TRANSPORT_ADDRESS Address;
    } BindRequest;
    static const struct
    {
        const char *What;
        LONG Count;
    } Cases[] =
    {
        { "zero", 0 },
        { "three", 3 },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
        if (!NT_SUCCESS(Status))
            return;

        RtlZeroMemory(&BindRequest, sizeof(BindRequest));
        BindRequest.Address.TAAddressCount = Cases[i].Count;

        Status = NtDeviceIoControlFile(SocketHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &IoStatus,
                                       IOCTL_AFD_BIND,
                                       &BindRequest,
                                       sizeof(BindRequest),
                                       NULL,
                                       0);
        ok(!NT_SUCCESS(Status), "bind with a count of %s succeeded with %lx\n",
           Cases[i].What, Status);

        NtClose(SocketHandle);
    }
}

/* build the IPv4 transport address the way msafd does: the unpadded wire
 * length (14) in the entry, inside a request padded past the address */
static
void
BuildMsafdIpv4Address(
    _Out_ PTRANSPORT_ADDRESS Address,
    _In_ ULONG AddressSize,
    _In_ ULONG IpAddress,
    _In_ USHORT Port)
{
    RtlZeroMemory(Address, AddressSize);
    Address->TAAddressCount = 1;
    Address->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    Address->Address[0].AddressLength =
        (USHORT)(sizeof(struct sockaddr_in) - FIELD_OFFSET(struct sockaddr, sa_data));
    ((PTDI_ADDRESS_IP)&Address->Address[0].Address)->sin_port = htons(Port);
    ((PTDI_ADDRESS_IP)&Address->Address[0].Address)->in_addr = IpAddress;
}

static
void
TestPaddedBind(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    IO_STATUS_BLOCK IoStatus;
    /* the msafd request is padded well past the 22 bytes the address uses */
    UCHAR Request[104];

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    BuildMsafdIpv4Address(&((PAFD_BIND_DATA)Request)->Address,
                          sizeof(Request) - FIELD_OFFSET(AFD_BIND_DATA, Address),
                          inet_addr("127.0.0.1"),
                          0);
    Status = NtDeviceIoControlFile(SocketHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_BIND,
                                   Request,
                                   sizeof(Request),
                                   NULL,
                                   0);
    ok(Status == STATUS_SUCCESS, "padded IPv4 bind failed with %lx\n", Status);

    NtClose(SocketHandle);
}

static
void
TestSendTo(void)
{
    NTSTATUS Status;
    HANDLE SocketHandle;
    struct sockaddr_in Addr;
    UCHAR Payload[4] = { 1, 2, 3, 4 };

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    RtlZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    Addr.sin_port = htons(9);

    Status = AfdBind(SocketHandle, (const struct sockaddr *)&Addr, sizeof(Addr));
    ok(Status == STATUS_SUCCESS, "AfdBind failed with %lx\n", Status);

    if (NT_SUCCESS(Status))
    {
        Status = AfdSendTo(SocketHandle, Payload, sizeof(Payload),
                           (const struct sockaddr *)&Addr, sizeof(Addr));
        ok(Status == STATUS_SUCCESS, "sendto failed with %lx\n", Status);
    }

    NtClose(SocketHandle);
}

static
void
TestConnectExWithData(void)
{
    NTSTATUS Status;
    HANDLE Listener = NULL, SocketHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Event = NULL;
    UCHAR Request[64];
    AFD_SUPER_CONNECT_INFO SuperConnect;
    struct sockaddr_in Addr;
    INT NameLength = sizeof(Addr);
    static const UCHAR ConnectData[8] = { 'C', 'O', 'N', 'N', 'E', 'C', 'T', 0 };

    {
        IO_STATUS_BLOCK ListenIosb;
        AFD_LISTEN_DATA ListenData;

        Status = AfdCreateSocket(&Listener, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(Status == STATUS_SUCCESS, "AfdCreateSocket(listener) failed with %lx\n", Status);
        if (!NT_SUCCESS(Status))
            return;

        RtlZeroMemory(&Addr, sizeof(Addr));
        Addr.sin_family = AF_INET;
        Addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        Addr.sin_port = 0;
        Status = AfdBind(Listener, (const struct sockaddr *)&Addr, sizeof(Addr));
        ok(Status == STATUS_SUCCESS, "AfdBind(listener) failed with %lx\n", Status);
        if (!NT_SUCCESS(Status)) goto Cleanup;

        RtlZeroMemory(&ListenData, sizeof(ListenData));
        ListenData.Backlog = 4;
        Status = NtDeviceIoControlFile(Listener,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ListenIosb,
                                       IOCTL_AFD_LISTEN,
                                       &ListenData,
                                       sizeof(ListenData),
                                       NULL,
                                       0);
        if (Status == STATUS_PENDING)
        {
            NtWaitForSingleObject(Listener, FALSE, NULL);
            Status = ListenIosb.Status;
        }
        ok(Status == STATUS_SUCCESS, "IOCTL_AFD_LISTEN failed with %lx\n", Status);
        if (!NT_SUCCESS(Status)) goto Cleanup;

        Status = AfdGetSockName(Listener, (struct sockaddr *)&Addr, &NameLength);
        ok(Status == STATUS_SUCCESS, "AfdGetSockName failed with %lx\n", Status);
        if (!NT_SUCCESS(Status)) goto Cleanup;
    }

    Status = AfdCreateSocket(&SocketHandle, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Status == STATUS_SUCCESS, "AfdCreateSocket failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    {
        struct sockaddr_in BindAddr;
        RtlZeroMemory(&BindAddr, sizeof(BindAddr));
        BindAddr.sin_family = AF_INET;
        BindAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        BindAddr.sin_port = 0;
        Status = AfdBind(SocketHandle, (const struct sockaddr *)&BindAddr, sizeof(BindAddr));
        ok(Status == STATUS_SUCCESS, "AfdBind failed with %lx\n", Status);
        if (!NT_SUCCESS(Status)) goto Cleanup;
    }

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(Status == STATUS_SUCCESS, "NtCreateEvent failed with %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    RtlZeroMemory(Request, sizeof(Request));
    RtlZeroMemory(&SuperConnect, sizeof(SuperConnect));
    BuildMsafdIpv4Address(&SuperConnect.RemoteAddress,
                          sizeof(SuperConnect) - FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress),
                          Addr.sin_addr.s_addr,
                          Addr.sin_port);
    RtlCopyMemory(Request, &SuperConnect, sizeof(SuperConnect));

    Status = NtDeviceIoControlFile(SocketHandle,
                                   Event,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   IOCTL_AFD_SUPER_CONNECT,
                                   Request,
                                   FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress) +
                                       FIELD_OFFSET(TRANSPORT_ADDRESS, Address) +
                                       FIELD_OFFSET(TA_ADDRESS, Address) +
                                       SuperConnect.RemoteAddress.Address[0].AddressLength,
                                   (PVOID)ConnectData,
                                   sizeof(ConnectData));
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Event, FALSE, NULL);
        Status = IoStatus.Status;
    }
    ok(Status == STATUS_SUCCESS, "super connect with data failed with %lx\n", Status);

Cleanup:
    if (Event) NtClose(Event);
    if (SocketHandle) NtClose(SocketHandle);
    if (Listener) NtClose(Listener);
}

void
func_ioctl(void)
{
    TestAcceptForeignHandle();
    TestNullBufferSend();
    TestMinimumLengths();
    TestSelect();
    TestConnect();
    TestShortAddress();
    TestCountZeroBind();
    TestPaddedBind();
    TestSendTo();
    TestConnectExWithData();
}

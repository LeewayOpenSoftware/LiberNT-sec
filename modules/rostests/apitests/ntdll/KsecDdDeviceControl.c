/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for control requests the security device does not handle
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

/* FILE_DEVICE_KSEC */
#define TEST_DEVICE_KSEC 0x39

/* A function number the device has never had */
#define TEST_IOCTL_KSEC_UNKNOWN_BUFFERED \
    CTL_CODE(TEST_DEVICE_KSEC, 0x7FF, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TEST_IOCTL_KSEC_UNKNOWN_NEITHER \
    CTL_CODE(TEST_DEVICE_KSEC, 0x7FE, METHOD_NEITHER, FILE_ANY_ACCESS)

/* IOCTL_KSEC_RANDOM_FILL_BUFFER */
#define TEST_IOCTL_KSEC_RANDOM_FILL_BUFFER \
    CTL_CODE(TEST_DEVICE_KSEC, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)

START_TEST(KsecDdDeviceControl)
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Device;
    NTSTATUS Status;
    UCHAR Buffer[64];
    ULONG Index, NonZero;

    /* Every process may open the device: it is where random numbers come from */
    InitializeObjectAttributes(&ObjectAttributes, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Device,
                        FILE_READ_DATA | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    ok(NT_SUCCESS(Status), "The security device could not be opened: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    /* A code the device does not know is refused, and the system goes on */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xA5);
    IoStatus.Status = STATUS_PENDING;
    IoStatus.Information = 0xDEADBEEF;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &IoStatus,
                                   TEST_IOCTL_KSEC_UNKNOWN_BUFFERED,
                                   Buffer, sizeof(Buffer), Buffer, sizeof(Buffer));
    ok(!NT_SUCCESS(Status), "An unknown buffered code succeeded with 0x%lx\n", Status);
    for (Index = 0; Index < sizeof(Buffer); Index++)
    {
        if (Buffer[Index] != 0xA5)
            break;
    }
    ok(Index == sizeof(Buffer), "An unknown code changed the buffer at byte %lu\n", Index);

    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &IoStatus,
                                   TEST_IOCTL_KSEC_UNKNOWN_NEITHER,
                                   NULL, 0, NULL, 0);
    ok(!NT_SUCCESS(Status), "An unknown code with no buffers succeeded with 0x%lx\n", Status);

    /* The device still does its work afterwards */
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &IoStatus,
                                   TEST_IOCTL_KSEC_RANDOM_FILL_BUFFER,
                                   NULL, 0, Buffer, sizeof(Buffer));
    ok(NT_SUCCESS(Status), "Random bytes were refused with 0x%lx\n", Status);
    NonZero = 0;
    for (Index = 0; Index < sizeof(Buffer); Index++)
    {
        if (Buffer[Index] != 0)
            NonZero++;
    }
    ok(!NT_SUCCESS(Status) || NonZero != 0, "Sixty-four random bytes were all zero\n");

    NtClose(Device);
}

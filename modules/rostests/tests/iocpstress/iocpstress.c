/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 Leeway Open Software
 *
 * Stress test for threads that leave an I/O completion port while the port
 * is closed. Each round creates a port, starts worker threads that take one
 * packet from it (which associates them with the port) and then leave in one
 * of several ways, and closes the last handle of the port at a random moment.
 *
 * Usage: iocpstress [rounds] [workers]
 * Prints one line every 100 rounds and "iocpstress: PASS" at the end. A
 * defect in the kernel shows as a stop or a hang, not as a failed check.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_WORKERS 64

typedef struct _WORKER
{
    HANDLE Port;
    HANDLE OtherPort;
    HANDLE Gate;
    ULONG Seed;
    ULONG Mode;
} WORKER;

static ULONG NextRandom(ULONG *Seed)
{
    *Seed = *Seed * 1103515245UL + 12345UL;
    return (*Seed >> 16) & 0x7FFF;
}

static void Spin(ULONG Count)
{
    volatile ULONG i;

    for (i = 0; i < Count; i++)
    {
    }
}

static DWORD WINAPI WorkerThread(LPVOID Parameter)
{
    WORKER *Worker = Parameter;
    DWORD Bytes;
    ULONG_PTR Key;
    LPOVERLAPPED Overlapped;

    /* Take one packet: from here the thread belongs to the port */
    GetQueuedCompletionStatus(Worker->Port, &Bytes, &Key, &Overlapped, 50);

    Spin(NextRandom(&Worker->Seed) * 4);

    switch (Worker->Mode)
    {
        case 0:
            /* End at once */
            break;

        case 1:
            /* Start an ordinary wait while still belonging to the port */
            WaitForSingleObject(Worker->Gate, NextRandom(&Worker->Seed) % 3);
            break;

        case 2:
            /* Move to another port */
            GetQueuedCompletionStatus(Worker->OtherPort, &Bytes, &Key, &Overlapped, 0);
            break;

        default:
            /* Go back to the port, which may be closed by now */
            GetQueuedCompletionStatus(Worker->Port, &Bytes, &Key, &Overlapped,
                                      NextRandom(&Worker->Seed) % 3);
            break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    static WORKER Workers[MAX_WORKERS];
    HANDLE Threads[MAX_WORKERS];
    HANDLE Port, OtherPort, Gate;
    ULONG Rounds = 2000, Count = 8, Round, i, Started;
    ULONG Seed = GetTickCount() | 1;
    DWORD ThreadId;

    if (argc > 1)
        Rounds = strtoul(argv[1], NULL, 10);
    if (argc > 2)
        Count = strtoul(argv[2], NULL, 10);
    if (Count == 0 || Count > MAX_WORKERS)
        Count = 8;

    printf("iocpstress: %lu rounds, %lu workers, seed %lu\n", Rounds, Count, Seed);

    Gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (Gate == NULL)
    {
        printf("iocpstress: FAIL CreateEvent %lu\n", GetLastError());
        return 1;
    }

    for (Round = 0; Round < Rounds; Round++)
    {
        Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        OtherPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (Port == NULL || OtherPort == NULL)
        {
            printf("iocpstress: FAIL CreateIoCompletionPort %lu (round %lu)\n", GetLastError(), Round);
            return 1;
        }

        /* One packet for each worker, so that each one is associated */
        for (i = 0; i < Count; i++)
            PostQueuedCompletionStatus(Port, 0, i, NULL);

        Started = 0;
        for (i = 0; i < Count; i++)
        {
            Workers[i].Port = Port;
            Workers[i].OtherPort = OtherPort;
            Workers[i].Gate = Gate;
            Workers[i].Seed = Seed + Round * 131 + i * 7919;
            Workers[i].Mode = NextRandom(&Seed) % 4;

            Threads[Started] = CreateThread(NULL, 0, WorkerThread, &Workers[i], 0, &ThreadId);
            if (Threads[Started] != NULL)
                Started++;
        }

        /* Close the last handle of the port at a random moment, while the
         * workers take their packet, wait, move or end */
        Spin(NextRandom(&Seed) * 16);
        if ((NextRandom(&Seed) & 3) == 0)
            Sleep(0);
        CloseHandle(Port);

        Spin(NextRandom(&Seed) * 4);
        CloseHandle(OtherPort);

        if (Started != 0)
            WaitForMultipleObjects(Started, Threads, TRUE, INFINITE);
        for (i = 0; i < Started; i++)
            CloseHandle(Threads[i]);

        if ((Round % 100) == 99)
            printf("iocpstress: round %lu\n", Round + 1);
    }

    CloseHandle(Gate);
    printf("iocpstress: PASS rounds=%lu workers=%lu\n", Rounds, Count);
    return 0;
}

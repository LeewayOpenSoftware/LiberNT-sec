/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     A user context whose instruction or stack pointer lies outside the user range
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <kmt_test.h>
#include <ndk/kefuncs.h>
#include <ndk/psfuncs.h>

#define RANGE_NON_CANONICAL 0x8000000000000000ULL
#define RANGE_KERNEL_ADDRESS 0xFFFFF80000000000ULL
#define RANGE_EXIT_CODE 0x5A5A0003

typedef struct _RANGE_FAULT
{
    DWORD ThreadId;
    LONG Hits;
    NTSTATUS Code;
    PVOID Address;
} RANGE_FAULT;

static RANGE_FAULT Fault;
static DWORD64 ContinueRip;

static
DECLSPEC_NORETURN
VOID
NTAPI
RangeExit(
    _In_ ULONG_PTR Code)
{
    ExitThread((DWORD)Code);
}

static
LONG
NTAPI
RangeHandler(
    _In_ PEXCEPTION_POINTERS Pointers)
{
    PCONTEXT Context = Pointers->ContextRecord;

    if (GetCurrentThreadId() != Fault.ThreadId)
        return EXCEPTION_CONTINUE_SEARCH;

    Fault.Hits++;
    Fault.Code = Pointers->ExceptionRecord->ExceptionCode;
    Fault.Address = Pointers->ExceptionRecord->ExceptionAddress;

    Context->Rsp = (Context->Rsp & ~(DWORD64)15) - 0x88;
    Context->Rip = (DWORD64)RangeExit;
    Context->Rcx = RANGE_EXIT_CODE;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static
DWORD
WINAPI
ContinueThread(
    _In_ PVOID Parameter)
{
    CONTEXT Context;

    UNREFERENCED_PARAMETER(Parameter);

    RtlCaptureContext(&Context);
    Context.ContextFlags = CONTEXT_FULL;
    Context.Rip = ContinueRip;
    Context.Rsp -= 0x100;
    NtContinue(&Context, FALSE);
    return 0;
}

static
DWORD
WINAPI
SetContextThread(
    _In_ PVOID Parameter)
{
    CONTEXT Context;

    UNREFERENCED_PARAMETER(Parameter);

    RtlCaptureContext(&Context);
    Context.ContextFlags = CONTEXT_CONTROL;
    Context.Rip = ContinueRip;
    Context.Rsp -= 0x100;
    NtSetContextThread(NtCurrentThread(), &Context);
    return 0;
}

/* Where the fault is reported is the kernel's choice; that it is the thread's fault, once, is not */
static
VOID
TestInstructionPointer(
    _In_ LPTHREAD_START_ROUTINE Routine,
    _In_ DWORD64 Rip)
{
    HANDLE Thread;
    DWORD Wait, ExitCode = 0;

    RtlZeroMemory(&Fault, sizeof(Fault));
    ContinueRip = Rip;
    Thread = CreateThread(NULL, 0x10000, Routine, NULL, CREATE_SUSPENDED, &Fault.ThreadId);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!Thread)
        return;

    ResumeThread(Thread);
    Wait = WaitForSingleObject(Thread, 10000);
    ok_eq_ulong(Wait, WAIT_OBJECT_0);
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateThread(Thread, 0);
        CloseHandle(Thread);
        return;
    }

    ok(GetExitCodeThread(Thread, &ExitCode), "GetExitCodeThread failed with %lu\n", GetLastError());
    ok_eq_hex(ExitCode, RANGE_EXIT_CODE);
    ok_eq_long(Fault.Hits, 1);
    ok_eq_hex(Fault.Code, STATUS_ACCESS_VIOLATION);
    trace("Rip %I64x: fault reported at %p\n", Rip, Fault.Address);

    CloseHandle(Thread);
}

/* Runs without a stack */
__attribute__((naked))
static
VOID
SpinWithoutStack(VOID)
{
    __asm__("1: pause; jmp 1b");
}

static volatile LONG SpinStarted;

static
DWORD
WINAPI
SpinThread(
    _In_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);

    SpinStarted = 1;
    for (;;)
        YieldProcessor();
}

/* The thread never touches its stack again, so a stack pointer outside the user range must not stop it or the machine */
static
VOID
TestStackPointer(
    _In_ DWORD64 Rsp)
{
    CONTEXT Context;
    HANDLE Thread;
    BOOL Success;
    ULONG Tries;

    SpinStarted = 0;
    Thread = CreateThread(NULL, 0x10000, SpinThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!Thread)
        return;

    for (Tries = 0; (Tries < 500) && !SpinStarted; Tries++)
        Sleep(10);
    ok(SpinStarted == 1, "The thread did not start\n");
    SuspendThread(Thread);

    RtlZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_CONTROL;
    Success = SpinStarted && GetThreadContext(Thread, &Context);
    ok(Success, "GetThreadContext failed with %lu\n", GetLastError());
    if (Success)
    {
        Context.ContextFlags = CONTEXT_CONTROL;
        Context.Rip = (DWORD64)SpinWithoutStack;
        Context.Rsp = Rsp;
        Success = SetThreadContext(Thread, &Context);
        trace("Rsp %I64x: SetThreadContext %s\n", Rsp, Success ? "accepted" : "refused");
    }

    if (Success)
    {
        ResumeThread(Thread);
        Sleep(200);
        ok(WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT, "The thread stopped running\n");
        SuspendThread(Thread);

        RtlZeroMemory(&Context, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL;
        ok(GetThreadContext(Thread, &Context), "GetThreadContext failed with %lu\n", GetLastError());
        ok((Context.Rip >= (DWORD64)SpinWithoutStack) && (Context.Rip < (DWORD64)SpinWithoutStack + 8),
           "The thread is at %I64x, not in its loop at %p\n", Context.Rip, SpinWithoutStack);
        trace("Rsp %I64x: the thread reports %I64x\n", Rsp, Context.Rsp);
    }

    TerminateThread(Thread, 0);
    ok_eq_ulong(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
    CloseHandle(Thread);
}

START_TEST(KeContextRange)
{
    PVOID Handler;

    Handler = RtlAddVectoredExceptionHandler(1, RangeHandler);
    ok(Handler != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Handler)
        return;

    TestInstructionPointer(ContinueThread, RANGE_NON_CANONICAL);
    TestInstructionPointer(SetContextThread, RANGE_NON_CANONICAL);
    TestInstructionPointer(ContinueThread, RANGE_KERNEL_ADDRESS);
    TestInstructionPointer(SetContextThread, RANGE_KERNEL_ADDRESS);

    RtlRemoveVectoredExceptionHandler(Handler);

    TestStackPointer(RANGE_NON_CANONICAL);
    TestStackPointer(RANGE_KERNEL_ADDRESS);
}

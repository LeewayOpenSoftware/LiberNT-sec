/*
 * PROJECT:     LiberNT Kernel
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel virtual address shadow: entry and exit transitions for amd64
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include <asm.inc>
#include <ksamd64.inc>

EXTERN KiUserIretqFault:PROC
EXTERN KiSystemCallEntry64Resume:PROC
EXTERN KiSystemCallEntry32Resume:PROC
EXTERN KeBugCheckEx:PROC

KVA_STUB_SIZE = 16
KVA_TRANSITION_FRAME = (PcKvaShadowTransitionStack + 4096 - 40)

.code64

MACRO(KvaShadowVectorStub, Target)
    push rax
    mov eax, Vector
    jmp Target
    ALIGN KVA_STUB_SIZE
ENDM

ALIGN KVA_STUB_SIZE
PUBLIC KiKvaShadowVectorStubs
KiKvaShadowVectorStubs:
Vector = 0
REPEAT 10
    KvaShadowVectorStub KiKvaShadowCommon
    Vector = Vector + 1
ENDR
REPEAT 5
    KvaShadowVectorStub KiKvaShadowCommonEc
    Vector = Vector + 1
ENDR
REPEAT 2
    KvaShadowVectorStub KiKvaShadowCommon
    Vector = Vector + 1
ENDR
REPEAT 1
    KvaShadowVectorStub KiKvaShadowCommonEc
    Vector = Vector + 1
ENDR
REPEAT 3
    KvaShadowVectorStub KiKvaShadowCommon
    Vector = Vector + 1
ENDR
REPEAT 1
    KvaShadowVectorStub KiKvaShadowCommonEc
    Vector = Vector + 1
ENDR
REPEAT 7
    KvaShadowVectorStub KiKvaShadowCommon
    Vector = Vector + 1
ENDR
REPEAT 2
    KvaShadowVectorStub KiKvaShadowCommonEc
    Vector = Vector + 1
ENDR
REPEAT 225
    KvaShadowVectorStub KiKvaShadowCommon
    Vector = Vector + 1
ENDR
PUBLIC KiKvaShadowVectorStubsEnd
KiKvaShadowVectorStubsEnd:

KiKvaShadowCommon:
    test byte ptr [rsp + 16], 3
    jz KiKvaShadowFromKernel

    swapgs
    mov gs:[PcKvaVector], eax
    mov rax, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rax
    pop rax
    mov gs:[PcKvaSavedRax], rax
    mov rax, rsp
    mov rsp, gs:[PcRspBase]
    push qword ptr [rax + 32]
    push qword ptr [rax + 24]
    push qword ptr [rax + 16]
    push qword ptr [rax + 8]
    push qword ptr [rax]
    jmp KiKvaShadowDispatchUser

KiKvaShadowFromKernel:
    mov rax, gs:[PcKvaShadowHandlers + rax * 8]
    push rax
    mov rax, [rsp + 8]
    ret 8

KiKvaShadowCommonEc:
    test byte ptr [rsp + 24], 3
    jz KiKvaShadowFromKernelEc

    swapgs
    mov gs:[PcKvaVector], eax
    mov rax, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rax
    pop rax
    mov gs:[PcKvaSavedRax], rax
    mov rax, rsp
    mov rsp, gs:[PcRspBase]
    push qword ptr [rax + 40]
    push qword ptr [rax + 32]
    push qword ptr [rax + 24]
    push qword ptr [rax + 16]
    push qword ptr [rax + 8]
    push qword ptr [rax]

KiKvaShadowDispatchUser:
    mov eax, gs:[PcKvaVector]
    mov rax, gs:[PcKvaShadowHandlers + rax * 8]
    push rax
    mov rax, gs:[PcKvaSavedRax]
    swapgs
    ret

KiKvaShadowFromKernelEc:
    push rcx
    lea rcx, KiKvaShadowExitIretqInstruction[rip]
    cmp [rsp + 24], rcx
    je KiKvaShadowExitFault
    lea rcx, KiKvaShadowExitSysretInstruction[rip]
    cmp [rsp + 24], rcx
    je KiKvaShadowExitFaultSysret
    pop rcx
    mov rax, gs:[PcKvaShadowHandlers + rax * 8]
    push rax
    mov rax, [rsp + 8]
    ret 8

KiKvaShadowExitFault:
    pop rcx
    swapgs
    mov rax, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rax
    pop rax
    mov gs:[PcKvaSavedRax], rax
    mov gs:[PcKvaSavedRcx], rcx
    mov rcx, [rsp]
    mov rax, [rsp + 32]
    mov rsp, gs:[PcRspBase]
    push qword ptr [rax + 32]
    push qword ptr [rax + 24]
    push qword ptr [rax + 16]
    push qword ptr [rax + 8]
    push qword ptr [rax]
    push rcx
    mov rax, gs:[PcKvaSavedRax]
    mov rcx, gs:[PcKvaSavedRcx]
    swapgs
    jmp KiUserIretqFault

KiKvaShadowExitFaultSysret:
    swapgs
    mov rax, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rax
    mov rsp, gs:[PcRspBase]
    sub rsp, 48
    mov ecx, UNEXPECTED_KERNEL_MODE_TRAP
    mov edx, 13
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp + 32], 0
    call KeBugCheckEx
    int 3

PUBLIC KiKvaShadowSystemCall64
KiKvaShadowSystemCall64:
    swapgs
    mov gs:[PcKvaUserRspShadow], rsp
    mov rsp, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rsp
    mov rsp, gs:[PcKvaUserRspShadow]
    mov gs:[PcUserRsp], rsp
    mov rsp, gs:[PcRspBase]
    jmp KiSystemCallEntry64Resume

PUBLIC KiKvaShadowSystemCall32
KiKvaShadowSystemCall32:
    swapgs
    mov gs:[PcKvaUserRspShadow], rsp
    mov rsp, gs:[PcKvaKernelDirectoryTableBase]
    mov cr3, rsp
    mov rsp, gs:[PcKvaUserRspShadow]
    mov gs:[PcUserRsp], rsp
    mov rsp, gs:[PcRspBase]
    jmp KiSystemCallEntry32Resume

PUBLIC KiKvaShadowExitIretq
KiKvaShadowExitIretq:
    mov gs:[PcKvaSavedRax], rax
    mov gs:[PcKvaSavedRcx], rcx
    mov rax, gs:[PcSelf]
    add rax, KVA_TRANSITION_FRAME
    mov rcx, [rsp]
    mov [rax], rcx
    mov rcx, [rsp + 8]
    mov [rax + 8], rcx
    mov rcx, [rsp + 16]
    mov [rax + 16], rcx
    mov rcx, [rsp + 24]
    mov [rax + 24], rcx
    mov rcx, [rsp + 32]
    mov [rax + 32], rcx
    mov rsp, rax
    mov rcx, gs:[PcKvaSavedRcx]
    mov rax, gs:[PcKvaUserDirectoryTableBase]
    mov cr3, rax
    mov rax, gs:[PcKvaSavedRax]
    swapgs
PUBLIC KiKvaShadowExitIretqInstruction
KiKvaShadowExitIretqInstruction:
    iretq

PUBLIC KiKvaShadowExitSysret
KiKvaShadowExitSysret:
    mov gs:[PcKvaSavedRax], rax
    mov rax, gs:[PcKvaUserDirectoryTableBase]
    mov cr3, rax
    mov rax, gs:[PcKvaSavedRax]
    swapgs
PUBLIC KiKvaShadowExitSysretInstruction
KiKvaShadowExitSysretInstruction:
    sysretq

END

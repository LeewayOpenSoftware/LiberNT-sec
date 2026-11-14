/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     A kernel address inside a D3DKMT structure is refused, not used
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */

#include "precomp.h"

/* Readable in kernel mode on every build: the kernel view of the shared user
 * data page. Only given where the call reads, so an old build that uses it
 * reads harmlessly and the test sees the call succeed. */
#define KERNEL_READABLE_ADDRESS ((PVOID)(sizeof(PVOID) == 8 ? (ULONG_PTR)0xFFFFF78000000000ULL : (ULONG_PTR)0xFFDF0000UL))
/* Not mapped: where a call writes, an old build faults instead of writing */
#define KERNEL_UNMAPPED_ADDRESS ((PVOID)(sizeof(PVOID) == 8 ? (ULONG_PTR)0xFFFF800000000000ULL : (ULONG_PTR)0x80000000UL))

typedef NTSTATUS (APIENTRY *PFN_D3DKMT_CALL)(PVOID);

static NTSTATUS
CallGuarded(PFN_D3DKMT_CALL Function, PVOID Argument)
{
    NTSTATUS Status;

    _SEH2_TRY
    {
        Status = Function(Argument);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return Status;
}

/* Read from a pointer inside the structure: the ramp */
static void
Test_GammaRamp(D3DKMT_HANDLE hDevice)
{
    PFN_D3DKMT_CALL pfn = (PFN_D3DKMT_CALL)LoadD3DKMTProc("D3DKMTSetGammaRamp");
    D3DKMT_SETGAMMARAMP Data;

    if (!pfn)
    {
        skip("D3DKMTSetGammaRamp not exported\n");
        return;
    }
    memset(&Data, 0, sizeof(Data));
    Data.hDevice = hDevice;
    Data.VidPnSourceId = 0;
    Data.Type = D3DDDI_GAMMARAMP_RGB256x3x16;
    Data.pGammaRampRgb256x3x16 = (D3DDDI_GAMMA_RAMP_RGB256x3x16 *)KERNEL_READABLE_ADDRESS;
    Data.Size = sizeof(D3DDDI_GAMMA_RAMP_RGB256x3x16);
    ok_failed(CallGuarded(pfn, &Data), "SetGammaRamp with a kernel ramp pointer\n");
}

/* Written through a pointer inside the structure: the private data */
static void
Test_QueryAdapterInfo(D3DKMT_HANDLE hAdapter)
{
    PFN_D3DKMT_CALL pfn = (PFN_D3DKMT_CALL)LoadD3DKMTProc("D3DKMTQueryAdapterInfo");
    D3DKMT_QUERYADAPTERINFO Data;

    if (!pfn)
    {
        skip("D3DKMTQueryAdapterInfo not exported\n");
        return;
    }
    memset(&Data, 0, sizeof(Data));
    Data.hAdapter = hAdapter;
    Data.Type = KMTQAITYPE_ADAPTERTYPE;
    Data.pPrivateDriverData = KERNEL_UNMAPPED_ADDRESS;
    Data.PrivateDriverDataSize = sizeof(D3DKMT_ADAPTERTYPE);
    ok_failed(CallGuarded(pfn, &Data), "QueryAdapterInfo with a kernel output pointer\n");
}

/* Read and written through a pointer inside the structure: the escape data */
static void
Test_Escape(D3DKMT_HANDLE hAdapter)
{
    PFN_D3DKMT_CALL pfn = (PFN_D3DKMT_CALL)LoadD3DKMTProc("D3DKMTEscape");
    D3DKMT_ESCAPE Data;

    if (!pfn)
    {
        skip("D3DKMTEscape not exported\n");
        return;
    }
    memset(&Data, 0, sizeof(Data));
    Data.hAdapter = hAdapter;
    Data.Type = D3DKMT_ESCAPE_DRIVERPRIVATE;
    Data.pPrivateDriverData = KERNEL_UNMAPPED_ADDRESS;
    Data.PrivateDriverDataSize = 16;
    ok_failed(CallGuarded(pfn, &Data), "Escape with a kernel private data pointer\n");
}

/* A service that hands the caller's pointer straight to the bridge: the
 * keyed mutex private data is read from a kernel address only if unfixed */
static void
Test_KeyedMutex2(void)
{
    PFN_D3DKMT_CALL pfn = (PFN_D3DKMT_CALL)LoadD3DKMTProc("D3DKMTCreateKeyedMutex2");
    D3DKMT_CREATEKEYEDMUTEX2 Data;

    if (!pfn)
    {
        skip("D3DKMTCreateKeyedMutex2 not exported
");
        return;
    }
    memset(&Data, 0, sizeof(Data));
    Data.pPrivateRuntimeData = KERNEL_READABLE_ADDRESS;
    Data.PrivateRuntimeDataSize = 16;
    ok_failed(CallGuarded(pfn, &Data), "CreateKeyedMutex2 with kernel private data
");
}

/* The structure pointer itself is a kernel address on a direct service */
static void
Test_DirectStructurePointer(void)
{
    PFN_D3DKMT_CALL pfn = (PFN_D3DKMT_CALL)LoadD3DKMTProc("D3DKMTGetOverlayState");

    if (!pfn)
    {
        skip("D3DKMTGetOverlayState not exported
");
        return;
    }
    ok_failed(CallGuarded(pfn, KERNEL_UNMAPPED_ADDRESS), "GetOverlayState with a kernel structure pointer
");
}

START_TEST(embedded_kptr)
{
    D3DKMT_HANDLE hAdapter, hDevice;

    hAdapter = OpenAdapterFromDisplay1();
    if (!hAdapter)
    {
        skip("Cannot open the \\\\.\\DISPLAY1 adapter\n");
        return;
    }

    Test_KeyedMutex2();
    Test_DirectStructurePointer();
    Test_QueryAdapterInfo(hAdapter);
    Test_Escape(hAdapter);

    hDevice = CreateTestDevice(hAdapter);
    if (hDevice)
    {
        Test_GammaRamp(hDevice);
        DestroyTestDevice(hDevice);
    }
    else
    {
        skip("Cannot create a device\n");
    }

    CloseAdapter(hAdapter);
}

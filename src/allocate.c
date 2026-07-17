#include "allocate.h"
#include "resolver.h"
#include "engine.h"

BOOL Win32Allocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    // Local process allocation
    if (ctx->hProcess == (HANDLE)-1)
    {
        ctx->pRemoteAddress = VirtualAlloc(NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);
        return ctx->pRemoteAddress != NULL;
    }

    // Remote process allocation
    ctx->pRemoteAddress = VirtualAllocEx(ctx->hProcess,
                                         NULL,
                                         ctx->payloadSize,
                                         MEM_COMMIT | MEM_RESERVE,
                                         protect);

    return ctx->pRemoteAddress != NULL;
}

BOOL DFRAllocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    if (!g_VirtualAllocEx)
        return FALSE;

    if (ctx->hProcess == (HANDLE)-1)
    {
        ctx->pRemoteAddress = VirtualAlloc(NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);
        return ctx->pRemoteAddress != NULL;
    }

    ctx->pRemoteAddress = g_VirtualAllocEx(ctx->hProcess,
                                           NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);

    return ctx->pRemoteAddress != NULL;
}

BOOL DirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    if (ctx->hProcess == (HANDLE)-1)
    {
        ctx->pRemoteAddress = VirtualAlloc(NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);
        return ctx->pRemoteAddress != NULL;
    }

    PVOID baseAddr = NULL;
    SIZE_T regionSize = ctx->payloadSize;

    NTSTATUS status = SysNtAllocateVirtualMemory(ctx->hProcess,
                                                 &baseAddr,
                                                 0,
                                                 &regionSize,
                                                 MEM_COMMIT | MEM_RESERVE,
                                                 protect);

    if (status == 0)
        ctx->pRemoteAddress = baseAddr;

    return (status == 0);
}

BOOL IndirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    if (ctx->hProcess == (HANDLE)-1)
    {
        ctx->pRemoteAddress = VirtualAlloc(NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);
        return ctx->pRemoteAddress != NULL;
    }

    NTSTATUS status = IndirectSysNtAllocateVirtualMemory(
        ctx->hProcess,
        &ctx->pRemoteAddress,
        0,
        &ctx->payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        protect);

    return (status == 0);
}

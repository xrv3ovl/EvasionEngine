#pragma once
#include <windows.h>
#include <winternl.h>

#include "hash_utils.h"
#include "hash_functions.h"
//#include "pe_loader.h"

// ============================================================
//  Hash‑Based Module Resolution (caller passes pre‑hashed value)
// ============================================================

// Generic hash-based module resolver.
// Caller passes:
//   - pre-hashed module name (targetHash)
//   - hash function pointer (fn)
PVOID GetModuleBaseManualGenericHash(
    HANDLE      hProcess,
    PVOID       pebAddr,
    DWORD       targetHash,
    hash_fn_t   fn
);

// Convenience wrapper (still accepts a string).
// For fully string-free operation, do NOT use this.
PVOID GetModuleBaseManualHash(
    PPEB        pebObject,
    const char* moduleName,
    hash_fn_t   fn
);


// ============================================================
//  Hash‑Based Export Resolution (caller passes pre‑hashed value)
// ============================================================

// Generic hash-based export resolver.
// Caller passes:
//   - pre-hashed function name (targetHash)
//   - hash function pointer (fn)
//   - ordinal (optional)
PVOID GetProcAddressManualGenericHash(
    HANDLE      hProcess,
    PVOID       moduleBase,
    DWORD       targetHash,
    hash_fn_t   fn,
    WORD        ordinal
);

// Convenience wrapper (still accepts a string).
// For fully string-free operation, do NOT use this.
PVOID GetProcAddressManualHash(
    HANDLE      hProcess,
    PVOID       moduleBase,
    const char* functionName,
    hash_fn_t   fn
);


// ============================================================
//  Forwarder Resolution
// ============================================================

// Hash-only forwarder resolver.
// NOTE: This is a stub unless you implement a hash→string map.
PVOID ResolveForwarderHash(
    HANDLE      hProcess,
    DWORD       forwarderHash,
    hash_fn_t   fn
);


// ============================================================
//  Optional Helpers (hash-only convenience)
// ============================================================

// Resolve module by pre-hashed name
PVOID HashResolveModule(
    HANDLE      hProcess,
    PVOID       pebAddr,
    DWORD       moduleHash,
    hash_fn_t   fn
);

// Resolve export by pre-hashed name
PVOID HashResolveExport(
    HANDLE      hProcess,
    PVOID       moduleBase,
    DWORD       functionHash,
    hash_fn_t   fn
);

PVOID GetModuleBaseManualHV(
    HANDLE        hProcess,
    PVOID         pebAddr,
    HASHED_VALUE* hv
);

PVOID GetProcAddressManualHV(
    HANDLE        hProcess,
    PVOID         moduleBase,
    HASHED_VALUE* hv
);

HMODULE GetModuleBaseManualHashed(PPEB peb, HASHED_VALUE hvModule);
PVOID GPAManualByHash(HMODULE moduleBase, HASHED_VALUE hvFunction);
DWORD GetSSNByHash(PPEB peb, HASHED_VALUE hvModule, HASHED_VALUE hvFunction);
#pragma once
#include "engine.h"

BOOL DispatchAllocate(PINJECTION_CONTEXT ctx, DWORD protect);
BOOL DispatchWrite   (PINJECTION_CONTEXT ctx, LPCVOID payload);
BOOL DispatchProtect (PINJECTION_CONTEXT ctx, DWORD prot, PDWORD oldProt);
BOOL DispatchInvoke  (PINJECTION_CONTEXT ctx);

/* Flavor-specific functions */
BOOL Win32Allocate(PINJECTION_CONTEXT ctx, DWORD protect);
BOOL DFRAllocate(PINJECTION_CONTEXT ctx, DWORD protect);
BOOL DirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect);
BOOL IndirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect);

BOOL Win32Write(PINJECTION_CONTEXT ctx, LPCVOID payload);
BOOL DFRWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);
BOOL DirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);
BOOL IndirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);

BOOL Win32Protect(PINJECTION_CONTEXT ctx, DWORD prot, PDWORD oldProt);
BOOL DFRProtect(PINJECTION_CONTEXT ctx, DWORD prot, PDWORD oldProt);
BOOL DirectProtect(PINJECTION_CONTEXT ctx, DWORD prot, PDWORD oldProt);
BOOL IndirectProtect(PINJECTION_CONTEXT ctx, DWORD prot, PDWORD oldProt);

BOOL Win32Invoke(PINJECTION_CONTEXT ctx);
BOOL DFRInvoke(PINJECTION_CONTEXT ctx);
BOOL DirectInvoke(PINJECTION_CONTEXT ctx);
BOOL IndirectInvoke(PINJECTION_CONTEXT ctx);

BOOL EngineInvoke(PINJECTION_CONTEXT ctx);
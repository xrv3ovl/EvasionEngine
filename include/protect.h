#pragma once
#include "engine.h"

BOOL Win32Protect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect);

BOOL DFRProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect);

BOOL DirectProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect);

BOOL IndirectProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect);
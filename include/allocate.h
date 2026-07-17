#pragma once
#include "engine.h"

BOOL Win32Allocate(PINJECTION_CONTEXT ctx, DWORD protect);

BOOL DFRAllocate(PINJECTION_CONTEXT ctx, DWORD protect);

BOOL DirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect);

BOOL IndirectAllocate(PINJECTION_CONTEXT ctx, DWORD protect);
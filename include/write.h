#pragma once
#include "engine.h"

BOOL Win32Write(PINJECTION_CONTEXT ctx, LPCVOID payload);

BOOL DFRWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);

BOOL DirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);

BOOL IndirectWrite(PINJECTION_CONTEXT ctx, LPCVOID payload);
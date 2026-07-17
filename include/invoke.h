#pragma once
#include "engine.h"

BOOL Win32Invoke(PINJECTION_CONTEXT ctx);

BOOL DFRInvoke(PINJECTION_CONTEXT ctx);

BOOL DirectInvoke(PINJECTION_CONTEXT ctx);

BOOL IndirectInvoke(PINJECTION_CONTEXT ctx);
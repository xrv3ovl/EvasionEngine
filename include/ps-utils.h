#pragma once
#include <windows.h>
#include "hash_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

DWORD FindPidByName(const wchar_t* processName);
DWORD FindPidByHash(const HASHED_VALUE* hv);
HANDLE GetProcessHandle(DWORD pid);

#ifdef __cplusplus
}
#endif
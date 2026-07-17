#pragma once
#include <windows.h>

extern P_VirtualAllocEx      g_VirtualAllocEx;
extern P_VirtualProtect      g_VirtualProtect;
extern P_VirtualProtectEx    g_VirtualProtectEx;
extern P_WriteProcessMemory  g_WriteProcessMemory;
extern P_CreateRemoteThread  g_CreateRemoteThread;
extern P_WaitForSingleObject g_WaitForSingleObject;
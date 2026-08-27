#include "unwindraven_integration.h"
#include "blueprint_library.h"

StackProfileEntry blueprint[] = {
    { L"C:\\Windows\\system32\\win32u.dll", "NtUserGetMessage", 0x14, FALSE, TRUE, 0 },
    { L"C:\\Windows\\system32\\USER32.dll", "GetMessageW", 0x22, FALSE, TRUE, 0 },
    { L"C:\\Windows\\system32\\KERNEL32.DLL", "BaseThreadInitThunk", 0x17, FALSE, TRUE, 0 },
    { L"C:\\Windows\\system32\\ntdll.dll", "RtlUserThreadStart", 0x2C, FALSE, TRUE, 0 }
};    

int bpCount = sizeof(blueprint) / sizeof(blueprint[0]);
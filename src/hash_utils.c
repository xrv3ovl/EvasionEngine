#pragma once

#include "hash_utils.h"

typedef DWORD (*hash_fn_t)(const char*);

hash_fn_t lookup_hash(hash_entry_t* reg, int count, const char* name)
{
    for (int i = 0; i < count; i++)
    {
        if (my_stricmp(reg[i].name, name) == 0)
            return reg[i].fn;
    }
    return NULL;
}

// good for debugging, bad for PIC safety
void list_hashes(hash_entry_t* reg, int count)
{
    for (int i = 0; i < count; i++)
        printf("%s\n", reg[i].name);
}

DWORD hash_api(hash_fn_t fn, const char* s)
{
    return fn(s);
}
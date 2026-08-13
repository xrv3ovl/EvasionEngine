#pragma once
#include <windows.h>

#include "hash_functions.h"

typedef DWORD (*hash_fn_t)(const char*);

typedef struct {
    const char* name;
    hash_fn_t   fn;
} hash_entry_t;

typedef struct {
    hash_fn_t algorithm;
    DWORD     hash;
} HASHED_VALUE;

hash_fn_t lookup_hash(hash_entry_t* reg, int count, const char* name);

DWORD hash_api(hash_fn_t fn, const char* s);

void list_hashes(hash_entry_t* reg, int count);
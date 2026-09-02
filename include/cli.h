#pragma once
#include "engine.h"

typedef struct _CLI_OPTIONS {
    //  the main Injection Context to by hydrated
    INJECTION_CONTEXT ctx;

    //  proecess injection stage flavors
    SYSCALL_FLAVOR allocFlavor;
    SYSCALL_FLAVOR writeFlavor;
    SYSCALL_FLAVOR protectFlavor;
    SYSCALL_FLAVOR invokeFlavor;
    
    //  payload details
    unsigned char *payload;
    size_t payloadSize;    

    //  callstack spoofing
    BOOL spoofCallstack;
    CSTECHNIQUE csTechnique;

    //  unmasking
    BOOL unmaskForWrite; 
    char* unmaskWriteAlgo;
    char* unmaskWriteKey;
    BOOL unmaskForInvoke;
    char* unmaskInvokeAlgo;
    char* unmaskInvokeKey;
} CLI_OPTIONS;

void print_usage(const char *app_name);
int parse_cli(int argc, char **argv, CLI_OPTIONS *opts);
static uint8_t parse_key(const char *s);
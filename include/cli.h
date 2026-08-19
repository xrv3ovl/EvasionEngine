#pragma once
#include "engine.h"

typedef struct _CLI_OPTIONS {
    INJECTION_CONTEXT ctx;

    SYSCALL_FLAVOR allocFlavor;
    SYSCALL_FLAVOR writeFlavor;
    SYSCALL_FLAVOR protectFlavor;
    SYSCALL_FLAVOR invokeFlavor;
    
    unsigned char *payload;
    size_t payloadSize;    

    BOOL spoofCallstack;
    CSTECHNIQUE csTechnique;
} CLI_OPTIONS;

void print_usage(const char *app_name);
int parse_cli(int argc, char **argv, CLI_OPTIONS *opts);
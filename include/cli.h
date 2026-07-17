#pragma once
#include "engine.h"

typedef struct _CLI_OPTIONS {
    SYSCALL_FLAVOR apiFlavor;
    INJECTION_CONTEXT ctx;
} CLI_OPTIONS;

void print_usage(const char *app_name);
int parse_cli(int argc, char **argv, CLI_OPTIONS *opts);
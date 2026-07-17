#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cli.h"
#include "payload.h"
#include "engine.h"

static SYSCALL_FLAVOR parse_flavor(const char *s)
{
    int v = strtol(s, NULL, 0);
    switch (v) {
        case 1: return FLAVOR_WIN32;
        case 2: return FLAVOR_DFR;
        case 3: return FLAVOR_DIRECT;
        case 4: return FLAVOR_INDIRECT;
        default:
            fprintf(stderr, "[ERROR] Invalid flavor '%s'. Must be 1–4.\n", s);
            exit(-1);
    }
}

void print_usage(const char *app_name)
{
    printf("Usage: %s [options]\n", app_name);
    printf("Options:\n");
    printf("  -h, --help                     Show this help message\n");
    printf("  -p, --pid <pid>                Target PID\n");
    printf("  -s, --spawn <path>             Spawn target process\n");
    printf("  --alloc-flavor <1-4>           Allocation flavor\n");
    printf("  --write-flavor <1-4>           Write flavor\n");
    printf("  --protect-flavor <1-4>         Protection flavor\n");
    printf("  --invoke-flavor <1-4>          Invocation flavor\n");
    printf("  -t, --technique <0>            Injection technique\n");
    printf("  -m, --module <name>            Module stomping target\n");
    printf("  -e, --export <name>            Export stomping target\n");
    printf("  -o, --offset <hex>             Offset for stomping\n");
}

int parse_cli(int argc, char **argv, CLI_OPTIONS *opts)
{
    memset(opts, 0, sizeof(*opts));

    // Default flavors (you can change these)
    opts->allocFlavor   = FLAVOR_WIN32;
    opts->writeFlavor   = FLAVOR_WIN32;
    opts->protectFlavor = FLAVOR_WIN32;
    opts->invokeFlavor  = FLAVOR_WIN32;

    opts->ctx.payloadSize = sizeof(mockShellcode);
    opts->ctx.technique   = DEFAULT;

    printf("--- Processing Arguments ---\n");

    for (int i = 1; i < argc; i++)
    {
        char *arg = argv[i];
        char *optarg = NULL;

        #define FETCH_OPTARG() \
            do { \
                if (i + 1 < argc) optarg = argv[++i]; \
                else { fprintf(stderr, "[ERROR] %s requires an argument.\n", arg); return -1; } \
            } while (0)

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            print_usage(argv[0]);
            return 1;
        }

        else if (!strcmp(arg, "-p") || !strcmp(arg, "--pid")) {
            FETCH_OPTARG();
            opts->ctx.targetPid = strtol(optarg, NULL, 0);
            printf("[*] targetPid = %d\n", opts->ctx.targetPid);
        }

        else if (!strcmp(arg, "-s") || !strcmp(arg, "--spawn")) {
            FETCH_OPTARG();
            opts->ctx.spawnPath = optarg;
            opts->ctx.spawnTarget = TRUE;
            printf("[*] spawnPath = %s\n", opts->ctx.spawnPath);
        }

        else if (!strcmp(arg, "--alloc-flavor")) {
            FETCH_OPTARG();
            opts->allocFlavor = parse_flavor(optarg);
            printf("[*] allocFlavor = %s\n", flavorName(opts->allocFlavor));
        }

        else if (!strcmp(arg, "--write-flavor")) {
            FETCH_OPTARG();
            opts->writeFlavor = parse_flavor(optarg);
            printf("[*] writeFlavor = %s\n", flavorName(opts->writeFlavor));
        }

        else if (!strcmp(arg, "--protect-flavor")) {
            FETCH_OPTARG();
            opts->protectFlavor = parse_flavor(optarg);
            printf("[*] protectFlavor = %s\n", flavorName(opts->protectFlavor));
        }

        else if (!strcmp(arg, "--invoke-flavor")) {
            FETCH_OPTARG();
            opts->invokeFlavor = parse_flavor(optarg);
            printf("[*] invokeFlavor = %s\n", flavorName(opts->invokeFlavor));
        }

        else if (!strcmp(arg, "-t") || !strcmp(arg, "--technique")) {
            FETCH_OPTARG();
            int tech = strtol(optarg, NULL, 0);
            if (tech == 0) {
                opts->ctx.technique = EARLY_BIRD;
                printf("[*] Using Early Bird technique.\n");
            } else {
                fprintf(stderr, "[ERROR] Invalid technique.\n");
                return -1;
            }
        }

        else if (!strcmp(arg, "-m") || !strcmp(arg, "--module")) {
            FETCH_OPTARG();
            opts->ctx.targetModule = optarg;
            opts->ctx.enableStomping = TRUE;
            printf("[*] targetModule = %s\n", optarg);
        }

        else if (!strcmp(arg, "-e") || !strcmp(arg, "--export")) {
            FETCH_OPTARG();
            opts->ctx.targetExport = optarg;
            opts->ctx.enableStomping = TRUE;
            printf("[*] targetExport = %s\n", optarg);
        }

        else if (!strcmp(arg, "-o") || !strcmp(arg, "--offset")) {
            FETCH_OPTARG();
            opts->ctx.targetOffset = strtoul(optarg, NULL, 16);
            opts->ctx.enableStomping = TRUE;
            printf("[*] targetOffset = %lu\n", (unsigned long)opts->ctx.targetOffset);
        }

        else {
            fprintf(stderr, "[ERROR] Unknown parameter: %s\n", arg);
            return -1;
        }

        #undef FETCH_OPTARG
    }

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cli.h"
#include "payload.h"

void print_usage(const char *app_name) {
    printf("Usage: %s [options]\n", app_name);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -p, --pid <pid>           Target PID\n");
    printf("  -s, --spawn <path>        Spawn target process\n");
    printf("  -a, --api <1-4>           API method\n");
    printf("  -t, --technique <0>       Injection technique\n");
    printf("  -m, --module <name>       Module stomping target\n");
    printf("  -e, --export <name>       Export stomping target\n");
    printf("  -o, --offset <hex>        Offset for stomping\n");
}

int parse_cli(int argc, char **argv, CLI_OPTIONS *opts) {
    memset(opts, 0, sizeof(*opts));

    opts->apiFlavor        = FLAVOR_DFR;
    opts->ctx.payloadSize  = sizeof(mockShellcode);
    opts->ctx.technique    = DEFAULT;

    printf("--- Processing Arguments ---\n");

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        char *optarg = NULL;

        #define FETCH_OPTARG() do { \
            if (i + 1 < argc) optarg = argv[++i]; \
            else { fprintf(stderr, "[ERROR] %s requires an argument.\n", arg); return -1; } \
        } while(0)

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

        else if (!strcmp(arg, "-a") || !strcmp(arg, "--api")) {
            FETCH_OPTARG();
            int api = strtol(optarg, NULL, 0);
            printf("[*] apiMethod = %d\n", api);

            switch (api) {
                case 1: opts->apiFlavor = FLAVOR_WIN32;    break;
                case 2: opts->apiFlavor = FLAVOR_DFR;      break;
                case 3: opts->apiFlavor = FLAVOR_DIRECT;   break;
                case 4: opts->apiFlavor = FLAVOR_INDIRECT; break;
                default:
                    fprintf(stderr, "[ERROR] Invalid API method.\n");
                    return -1;
            }
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

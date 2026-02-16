#include "cli.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static void print_help(char *program_name);

cli_t load_cli(const int argc, char *argv[]) {
#define conf_opt_ind 0
#define help_opt_ind 1

    const struct option long_options[] = {
        {"conf", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    cli_t cli = {0};
    while (1) {
        int opt_ind;
        int c = getopt_long(argc, argv, "c:vh", long_options, &opt_ind);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                switch (opt_ind) {
                    case conf_opt_ind:
                        cli.config_file = optarg;
                        break;
                    case help_opt_ind: default:
                        print_help(argv[0]);
                        break;
                }
            case 'c':
                cli.config_file = optarg;
                break;
            case 'v':
                cli.verbose = true;
                break;
            case 'h':
                print_help(argv[0]);
                break;
            case '?': default: {
                printf("\n");
                print_help(argv[0]);
                break;
            }
        }
    }

    if (optind < argc) {
        printf("%s: invalid argument \'%s\'\n\n", argv[0], argv[optind]);
        print_help(argv[0]);
    }

    if (!cli.config_file) {
        printf("%s: option '--conf' is required\n\n", argv[0]);
        print_help(argv[0]);
    }

    return cli;
}

static void print_help(char *program_name) {
    printf("Usage: %s -c <config_file> [-d]\n\n", program_name);
    printf("Analyzes network packets from nfqueue.\n\n");
    printf("Options:\n");
    printf("  -c, --conf <config_file>  Specify configuration file.\n");
    printf("  -d, --debug               Enable debug mode.\n");
    printf("  -h, --help                Show this help message.\n");
    exit(0);
}

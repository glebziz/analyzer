#pragma once

#include <stdbool.h>

typedef struct {
    bool verbose;
    const char *config_file;
} cli_t;

cli_t load_cli(int argc, char *argv[]);

#pragma once

#include "config.h"

typedef struct app_t app_t;

app_t *app_init(const config_t *cfg);

int app_run(const app_t *a);

void app_free(app_t **a);

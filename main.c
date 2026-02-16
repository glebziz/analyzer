#include "app.h"
#include "cli.h"
#include "log.h"

int main(const int argc, char *argv[]) {
    cli_t cli = load_cli(argc, argv);
    log_set_level(cli.verbose ? LOG_DEBUG : LOG_INFO);

    config_t cfg;
    if (parse_config(cli.config_file, &cfg)) {
        return -1;
    }

    app_t *app = app_init(&cfg);
    if (!app) {
        return -1;
    }

    if (app_run(app)) {
        return -1;
    }

    app_free(&app);

    return 0;
}

#include "log.h"

#include <stdio.h>

void log_event(LogEvent event, LogStatus status)
{
    static const char *const event_names[] = {
        "vault_create",
        "vault_unlock",
        "vault_import",
        "record_add",
        "record_update",
        "record_delete",
        "vault_save"
    };
    const char *status_name;

    if ((unsigned int)event >= sizeof(event_names) / sizeof(event_names[0])) {
        return;
    }

    switch (status) {
        case LOG_STATUS_SUCCESS:
            status_name = "success";
            break;
        case LOG_STATUS_FAILURE:
            status_name = "failure";
            break;
        default:
            return;
    }

    fprintf(stderr, "event=%s status=%s\n", event_names[event], status_name);
}

#ifndef PWMAN_LOG_H
#define PWMAN_LOG_H

typedef enum {
    LOG_EVENT_VAULT_CREATE,
    LOG_EVENT_VAULT_UNLOCK,
    LOG_EVENT_VAULT_IMPORT,
    LOG_EVENT_RECORD_ADD,
    LOG_EVENT_RECORD_UPDATE,
    LOG_EVENT_RECORD_DELETE,
    LOG_EVENT_VAULT_SAVE
} LogEvent;

typedef enum {
    LOG_STATUS_SUCCESS,
    LOG_STATUS_FAILURE
} LogStatus;

void log_event(LogEvent event, LogStatus status);

#endif

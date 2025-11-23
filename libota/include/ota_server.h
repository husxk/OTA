#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ota_common.h"
#include "tls_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// Server context structure
typedef struct
{
    // Common OTA context
    OTA_common_ctx_t common;

    // Server-specific callbacks
    bool (*server_get_payload_cb) (void* ctx,
                                   const uint8_t** data,
                                   size_t* size);

    void (*server_transfer_progress_cb) (void* ctx,
                                         uint32_t bytes_sent,
                                         uint32_t packet_number);

} OTA_server_ctx;

// Initialize OTA server context
// Returns: 0 on success, negative value on error
int OTA_server_init(OTA_server_ctx* ctx);

bool OTA_server_run_transfer(OTA_server_ctx* ctx, void* user_ctx);

// Cleanup OTA server context and free resources
// Returns: 0 on success, negative value on error
int OTA_server_cleanup(OTA_server_ctx* ctx);

#ifdef __cplusplus
}
#endif


#pragma once

#include "libota/ota_server.h"
#include "libota/ota_common.h"

// Internal: Server-specific callbacks structure
typedef struct
{
    // Gets next payload chunk for transfer
    // Returns: true if data available, false if no more data
    bool (*server_get_payload_cb)(void* ctx,
                                  const uint8_t** data,
                                  size_t* size);

    // Called to report transfer progress
    void (*server_transfer_progress_cb)(void* ctx,
                                       uint32_t bytes_sent,
                                       uint32_t packet_number);

} OTA_server_callbacks_t;

// Internal: Full server context structure definition
struct ota_server_ctx
{
    // Common OTA context (includes common callbacks)
    OTA_common_ctx_t common;

    // Server-specific callbacks
    bool (*server_get_payload_cb)(void* ctx,
                                 const uint8_t** data,
                                 size_t* size);

    void (*server_transfer_progress_cb)(void* ctx,
                                       uint32_t bytes_sent,
                                       uint32_t packet_number);
};

// Note: OTA_server_callbacks_t matches the callback fields in struct ota_server_ctx
// for consistency with client implementation

// Internal: Initialize OTA server context
// Returns: 0 on success, negative value on error
int ota_server_init(OTA_server_ctx* ctx);

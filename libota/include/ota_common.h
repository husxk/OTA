#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    // Network transfer callbacks
    // Sends data over the network connection
    void (*transfer_send_cb) (void* ctx,
                              const uint8_t* data,
                              size_t size);

    // Receives data from the network connection
    // Returns: number of bytes actually received
    size_t (*transfer_receive_cb) (void* ctx,
                                   uint8_t* buffer,
                                   size_t max_size);

    // Handles transfer errors
    void (*transfer_error_cb) (void* ctx,
                               const char* error_msg);

    // Called when transfer is successfully completed
    void (*transfer_done_cb) (void* ctx,
                              uint32_t total_bytes);

    // Debug/Logging callback
    void (*debug_log_cb) (void* ctx, const char* format, ...);

} OTA_common_callbacks_t;

typedef struct
{
    OTA_common_callbacks_t callbacks;

} OTA_common_ctx_t;

void OTA_debug_log(OTA_common_ctx_t* common_ctx,
                   void* user_ctx,
                   const char* format,
                   ...);

bool OTA_send_ack_packet(OTA_common_ctx_t* common_ctx, void* user_ctx);

bool OTA_send_nack_packet(OTA_common_ctx_t* common_ctx, void* user_ctx);

bool OTA_send_fin_packet(OTA_common_ctx_t* common_ctx, void* user_ctx);

#ifdef __cplusplus
}
#endif

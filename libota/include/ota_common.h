#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common transfer callbacks shared between client and server
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
    void (*debug_log_cb) (void* ctx,
                          const char* format,
                          va_list args);

} OTA_common_callbacks_t;

// Common OTA context structure
typedef struct
{
    // Common callbacks
    OTA_common_callbacks_t callbacks;

} OTA_common_ctx_t;

// Common debug logging function
void OTA_common_debug_log(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const char* format,
                          ...);

#ifdef __cplusplus
}
#endif

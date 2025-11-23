#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include "tls_context.h"

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

// Common OTA context structure (full definition)
struct ota_common_ctx
{
    // Common callbacks
    OTA_common_callbacks_t callbacks;

    // TLS context
    tls_context_t tls;

};

// Common debug logging function
void ota_common_debug_log(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const char* format,
                          ...);

// Common send wrapper function
// Uses TLS if available, otherwise calls transfer_send_cb
void OTA_send_data(OTA_common_ctx_t* ctx,
                   void* user_ctx,
                   const uint8_t* data,
                   size_t size);

// Common receive wrapper function
// Uses TLS if available, otherwise calls transfer_receive_cb
// Returns: number of bytes received on success, 0 on error or no data
size_t OTA_recv_data(OTA_common_ctx_t* ctx,
                     void* user_ctx,
                     uint8_t* buffer,
                     size_t max_size);

// Set entropy callback for TLS
// Returns: 0 on success, negative value on error
int OTA_set_entropy_cb(tls_entropy_cb_t entropy_cb, void* entropy_ctx);

// Initialize TLS context
// endpoint: MBEDTLS_SSL_IS_SERVER for server mode, MBEDTLS_SSL_IS_CLIENT for client mode
// Returns: 0 on success, negative value on error
int ota_common_tls_init(OTA_common_ctx_t* ctx, int endpoint);

// Cleanup TLS context
// Returns: 0 on success, negative value on error
int ota_common_tls_cleanup(OTA_common_ctx_t* ctx);

// Set PKI data (certificate and private key) for TLS server mode
// Must be called before OTA_server_init on the common context's TLS member
// Data is stored as shallow copy.
// Returns: 0 on success, negative value on error
int OTA_set_pki_data(tls_context_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len);

#ifdef __cplusplus
}
#endif

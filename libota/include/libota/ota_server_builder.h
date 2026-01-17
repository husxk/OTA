#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include "libota/ota_server.h"
#include "libota/tls_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque builder type
typedef struct ota_server_builder OTA_server_builder_t;

// Error codes for build() function
#define OTA_SERVER_BUILDER_SUCCESS           0
#define OTA_SERVER_BUILDER_ERROR_NULL        -1
#define OTA_SERVER_BUILDER_ERROR_MISSING_CB  -2
#define OTA_SERVER_BUILDER_ERROR_ALLOC       -3

// Create a new server builder
// Returns: builder instance or NULL on error
OTA_server_builder_t* OTA_server_builder_create(void);

// Destroy a builder (frees all resources)
// Safe to call with NULL
void OTA_server_builder_destroy(OTA_server_builder_t* builder);

// Build and validate the context from the builder
// Validates all required callbacks and dependencies
// Allocates and initializes OTA_server_ctx internally
// Returns: context instance or NULL on error
// error_code: output parameter for error code (can be NULL)
OTA_server_ctx*
OTA_server_builder_build(OTA_server_builder_t* builder, int* error_code);

// Common callback setters
void
OTA_server_builder_set_transfer_send_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const uint8_t* data,
                                                   size_t size));

void
OTA_server_builder_set_transfer_receive_cb(OTA_server_builder_t* builder,
                                           size_t (*cb)(void* ctx,
                                                        uint8_t* buffer,
                                                        size_t max_size));

void
OTA_server_builder_set_transfer_error_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const char* error_msg));

void
OTA_server_builder_set_transfer_done_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   uint32_t total_bytes));

void
OTA_server_builder_set_debug_log_cb(OTA_server_builder_t* builder,
                                    void (*cb)(void* ctx,
                                               const char* format,
                                               va_list args));

// Server-specific callback setters
void
OTA_server_builder_set_server_get_payload_cb(OTA_server_builder_t* builder,
                                            bool (*cb)(void* ctx,
                                                       const uint8_t** data,
                                                       size_t* size));

void
OTA_server_builder_set_server_transfer_progress_cb(OTA_server_builder_t* builder,
                                                    void (*cb)(void* ctx,
                                                               uint32_t bytes_sent,
                                                               uint32_t packet_number));

// Configuration setters
// Set entropy callback for TLS (must be called before build if TLS is enabled)
// Returns: 0 on success, negative value on error
int
OTA_server_builder_set_entropy_cb(OTA_server_builder_t* builder,
                                  tls_entropy_cb_t entropy_cb,
                                  void* entropy_ctx);

// Enable TLS transport
// Returns: 0 on success, negative value on error
int
OTA_server_builder_enable_tls(OTA_server_builder_t* builder);

// Set PKI data for TLS (certificate + private key)
// Returns: 0 on success, negative value on error
int
OTA_server_builder_set_pki_data(OTA_server_builder_t* builder,
                                const unsigned char* cert_data,
                                size_t cert_len,
                                const unsigned char* key_data,
                                size_t key_len);

// Set SHA-512 private key for signing
// Returns: 0 on success, negative value on error
int
OTA_server_builder_set_sha512_private_key(OTA_server_builder_t* builder,
                                          const unsigned char* key_data,
                                          size_t key_len);

#ifdef __cplusplus
}
#endif

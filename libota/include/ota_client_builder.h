#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include "ota_client.h"
#include "tls_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque builder type
typedef struct ota_client_builder OTA_client_builder_t;

// Error codes for build() function
#define OTA_CLIENT_BUILDER_SUCCESS           0
#define OTA_CLIENT_BUILDER_ERROR_NULL        -1
#define OTA_CLIENT_BUILDER_ERROR_MISSING_CB  -2
#define OTA_CLIENT_BUILDER_ERROR_ALLOC       -3

// Create a new client builder
// Returns: builder instance or NULL on error
OTA_client_builder_t* OTA_client_builder_create(void);

// Destroy a builder (frees all resources)
// Safe to call with NULL
void OTA_client_builder_destroy(OTA_client_builder_t* builder);

// Build and validate the context from the builder
// Validates all required callbacks and dependencies
// Allocates and initializes OTA_client_ctx internally
// Returns: context instance or NULL on error
// error_code: output parameter for error code (can be NULL)
OTA_client_ctx*
OTA_client_builder_build(OTA_client_builder_t* builder, int* error_code);

// Common callback setters
void
OTA_client_builder_set_transfer_send_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const uint8_t* data,
                                                   size_t size));

void
OTA_client_builder_set_transfer_receive_cb(OTA_client_builder_t* builder,
                                           size_t (*cb)(void* ctx,
                                                        uint8_t* buffer,
                                                        size_t max_size));

void
OTA_client_builder_set_transfer_error_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const char* error_msg));

void
OTA_client_builder_set_transfer_done_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   uint32_t total_bytes));

void
OTA_client_builder_set_debug_log_cb(OTA_client_builder_t* builder,
                                    void (*cb)(void* ctx,
                                               const char* format,
                                               va_list args));

// Client-specific callback setters
void
OTA_client_builder_set_firmware_reboot_cb(OTA_client_builder_t* builder,
                                          void (*cb)(void));

void
OTA_client_builder_set_firmware_read_cb(OTA_client_builder_t* builder,
                                       void (*cb)(void* ctx,
                                                 uint32_t current_addr,
                                                 const uint8_t** data,
                                                 size_t* size));

void
OTA_client_builder_set_firmware_prepare_cb(OTA_client_builder_t* builder,
                                          void (*cb)(void* ctx));

void
OTA_client_builder_set_firmware_write_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   uint32_t flash_addr,
                                                   const uint8_t* data,
                                                   size_t size));

void
OTA_client_builder_set_transfer_store_cb(OTA_client_builder_t* builder,
                                        bool (*cb)(void* ctx,
                                                   const uint8_t* data,
                                                   size_t size));

void
OTA_client_builder_set_transfer_reset_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx));

// Configuration setters
// Set entropy callback for TLS (must be called before build if TLS is enabled)
// Returns: 0 on success, negative value on error
int
OTA_client_builder_set_entropy_cb(OTA_client_builder_t* builder,
                                  tls_entropy_cb_t entropy_cb,
                                  void* entropy_ctx);

// Enable TLS transport
// Returns: 0 on success, negative value on error
int
OTA_client_builder_enable_tls(OTA_client_builder_t* builder);

// Set SHA-512 public key for signature verification
// Returns: 0 on success, negative value on error
int
OTA_client_builder_set_sha512_public_key(OTA_client_builder_t* builder,
                                         const unsigned char* key_data,
                                         size_t key_len);

#ifdef __cplusplus
}
#endif

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Include the generated OTA_RAM_FUNCTION definition
#include "ota_ram_function.h"
#include "libota/ota_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Client context structure (opaque)
typedef struct ota_client_ctx OTA_client_ctx;

void OTA_client_setup_memory(OTA_client_ctx* ctx,
                             uint32_t ota_storage_start,
                             uint32_t ota_storage_end,
                             uint32_t flash_start);

// Cleanup OTA client context and free resources
// Returns: 0 on success, negative value on error
int OTA_client_cleanup(OTA_client_ctx* ctx);

// Destroy OTA client context (cleanup + free)
// Frees all resources and the context itself
// Safe to call with NULL
void OTA_client_destroy(OTA_client_ctx* ctx);

// Reset OTA client context state for reuse
// Cleans up runtime state but preserves callbacks and configuration
// Returns: 0 on success, negative value on error
int OTA_client_reset(OTA_client_ctx* ctx);

// TLS operations (wrapper functions for common context)
// Restart TLS context for reconnection (preserves SHA-512 keys)
// Returns: 0 on success, negative value on error
int OTA_client_tls_restart(OTA_client_ctx* ctx);

// Check if TLS is enabled
// Returns: true if TLS is enabled, false otherwise
bool OTA_client_tls_is_enabled(OTA_client_ctx* ctx);

// Check if TLS handshake is complete
// Returns: true if handshake is complete, false otherwise
bool OTA_client_tls_is_handshake_complete(OTA_client_ctx* ctx);

bool OTA_RAM_FUNCTION(OTA_client_write_firmware)(OTA_client_ctx* ctx, void* user_ctx);

bool OTA_client_handle_data(OTA_client_ctx* ctx,
                            void* user_ctx);

// RAM function for memory operations
void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n);

#ifdef __cplusplus
}
#endif


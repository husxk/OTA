#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "libota/ota_common.h"
#include "libota/tls_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// Server context structure (opaque)
typedef struct ota_server_ctx OTA_server_ctx;

bool OTA_server_run_transfer(OTA_server_ctx* ctx, void* user_ctx);

// Cleanup OTA server context and free resources
// Returns: 0 on success, negative value on error
int OTA_server_cleanup(OTA_server_ctx* ctx);

// Destroy OTA server context (cleanup + free)
// Frees all resources and the context itself
// Safe to call with NULL
void OTA_server_destroy(OTA_server_ctx* ctx);

// Reset OTA server context state for reuse
// Cleans up runtime state but preserves callbacks and configuration
// Returns: 0 on success, negative value on error
int OTA_server_reset(OTA_server_ctx* ctx);

#ifdef __cplusplus
}
#endif


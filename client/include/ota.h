#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "libota/ota_client.h"
#include "libota/ota_client_builder.h"
#include "libota/ota_common.h"
#include "libota/protocol.h"
#include "libota/tls_context.h"

// Forward declaration for entropy callback
extern int entropy_callback(void* ctx, unsigned char* output, size_t len);

#ifdef __cplusplus
extern "C" {
#endif

OTA_client_ctx* init_ota(void);

#ifdef __cplusplus
}
#endif

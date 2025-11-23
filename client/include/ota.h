#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "libota/ota_client.h"
#include "libota/ota_common.h"
#include "libota/protocol.h"

// Forward declaration for entropy callback
extern int entropy_callback(void* ctx, unsigned char* output, size_t len);

#ifdef __cplusplus
extern "C" {
#endif

int init_ota(OTA_client_ctx* ctx);

#ifdef __cplusplus
}
#endif

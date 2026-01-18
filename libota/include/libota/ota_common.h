#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include "libota/protocol.h"
#include <psa/crypto.h>
#include <mbedtls/pk.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common OTA context structure
typedef struct ota_common_ctx OTA_common_ctx_t;

#ifdef __cplusplus
}
#endif

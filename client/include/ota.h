#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Public libota client API (from pkg-config installed headers)
#include "libota/ota_client.h"
#include "libota/ota_common.h"
#include "libota/protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

int init_ota(OTA_client_ctx* ctx);

// Resets client-side OTA write offsets is declared in device.h

#ifdef __cplusplus
}
#endif

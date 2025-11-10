#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "libota/ota_client.h"
#include "libota/ota_common.h"
#include "libota/protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

int init_ota(OTA_client_ctx* ctx);

#ifdef __cplusplus
}
#endif

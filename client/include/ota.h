#pragma once

#include "pico/stdlib.h"
#include "libota/ota.h"

int init_ota(ota_config_t* ota_ctx);

void setup_ota_memory(ota_config_t* ota_ctx,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start);

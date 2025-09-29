#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Include the generated OTA_RAM_FUNCTION definition
#include "ota_ram_function.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint32_t ota_storage_start;  // Start address of OTA storage area
    uint32_t ota_storage_end;    // End address of OTA storage area
    uint32_t flash_start;        // Start address of main flash to write to
} ota_memory_t;

typedef struct
{
    void (*reboot_cb)(void); // called after flash update to reboot device

    void (*get_data_cb)(void* ctx,
                        uint32_t current_addr,
                        const uint8_t** data,
                        size_t* size); // called to get data for OTA buffer

    void (*pre_write_cb)(void* ctx); // called before starting firmware write
                                     // (e.g., to disable interrupts)

    void (*write_flash_cb)(void* ctx,
                           uint32_t flash_addr,
                           const uint8_t* data,
                           size_t size); // called to write data to flash

    ota_memory_t memory;  // Memory configuration
} ota_config_t;

void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n);

void OTA_setup_memory(ota_config_t* config,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start);

bool OTA_RAM_FUNCTION(OTA_write_firmware)(ota_config_t* config, void* ctx);

#ifdef __cplusplus
}
#endif

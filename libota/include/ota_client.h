#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Include the generated OTA_RAM_FUNCTION definition
#include "ota_ram_function.h"
#include "ota_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Client-specific memory configuration structure
typedef struct
{
    uint32_t ota_storage_start;  // Start address of OTA storage area
    uint32_t ota_storage_end;    // End address of OTA storage area
    uint32_t flash_start;        // Start address of main flash to write to
} OTA_memory_t;

// Client context structure
typedef struct
{
    // Common OTA context (includes common callbacks)
    OTA_common_ctx_t common;

    // Client-specific memory configuration
    OTA_memory_t memory;

    // Firmware update callbacks (must be in RAM)
    // Performs system reboot after successful firmware update
    // This callback should never return as the system will restart
    void (*firmware_reboot_cb) (void);

    // Reads firmware data from OTA storage area
    // Called during firmware update to retrieve data chunks from storage
    void (*firmware_read_cb) (void* ctx,
                              uint32_t current_addr,
                              const uint8_t** data,
                              size_t* size);

    // Prepares flash memory for writing (e.g., erasing sectors)
    // Called once before starting the firmware update process
    void (*firmware_prepare_cb) (void* ctx);

    // Writes firmware data to main flash memory
    // Called for each data chunk during firmware update
    void (*firmware_write_cb) (void* ctx,
                               uint32_t flash_addr,
                               const uint8_t* data,
                               size_t size);

    // Client-specific transfer callbacks
    // Stores received data to local storage (e.g., flash memory)
    // Returns: true if successful, false on error
    bool (*transfer_store_cb) (void* ctx,
                               const uint8_t* data,
                               size_t size);

    // Resets the transfer state (e.g., clears storage offset)
    // Called when transfer fails or needs to be restarted
    void (*transfer_reset_cb) (void* ctx);

} OTA_client_ctx;

void OTA_client_setup_memory(OTA_client_ctx* ctx,
                             uint32_t ota_storage_start,
                             uint32_t ota_storage_end,
                             uint32_t flash_start);

// Initialize OTA client context
// Returns: 0 on success, negative value on error
int OTA_client_init(OTA_client_ctx* ctx);

// Cleanup OTA client context and free resources
// Returns: 0 on success, negative value on error
int OTA_client_cleanup(OTA_client_ctx* ctx);

bool OTA_RAM_FUNCTION(OTA_client_write_firmware)(OTA_client_ctx* ctx, void* user_ctx);

bool OTA_client_handle_data(OTA_client_ctx* ctx,
                            void* user_ctx);

// RAM function for memory operations
void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n);

#ifdef __cplusplus
}
#endif


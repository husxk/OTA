#pragma once

#include "libota/ota_client.h"
#include "internal/ota_common.h"
#include "libota/ota_common.h"

// Internal: Client-specific memory configuration structure
typedef struct
{
    uint32_t ota_storage_start;  // Start address of OTA storage area
    uint32_t ota_storage_end;    // End address of OTA storage area
    uint32_t flash_start;        // Start address of main flash to write to
} OTA_memory_t;

// Internal: Client-specific callbacks structure
typedef struct
{
    // Firmware update callbacks (must be in RAM)
    // Performs system reboot after successful firmware update
    // This callback should never return as the system will restart
    void (*firmware_reboot_cb)(void);

    // Reads firmware data from OTA storage area
    // Called during firmware update to retrieve data chunks from storage
    void (*firmware_read_cb)(void* ctx,
                             uint32_t current_addr,
                             const uint8_t** data,
                             size_t* size);

    // Prepares flash memory for writing (e.g., erasing sectors)
    // Called once before starting the firmware update process
    void (*firmware_prepare_cb)(void* ctx);

    // Writes firmware data to main flash memory
    // Called for each data chunk during firmware update
    void (*firmware_write_cb)(void* ctx,
                              uint32_t flash_addr,
                              const uint8_t* data,
                              size_t size);

    // Client-specific transfer callbacks
    // Stores received data to local storage (e.g., flash memory)
    // Returns: true if successful, false on error
    bool (*transfer_store_cb)(void* ctx,
                              const uint8_t* data,
                              size_t size);

    // Resets the transfer state (e.g., clears storage offset)
    // Called when transfer fails or needs to be restarted
    void (*transfer_reset_cb)(void* ctx);

} OTA_client_callbacks_t;

// Internal: Full client context structure definition
struct ota_client_ctx
{
    // Common OTA context (includes common callbacks)
    OTA_common_ctx_t common;

    // Client-specific memory configuration
    OTA_memory_t memory;

    // Firmware update callbacks (must be in RAM)
    // Performs system reboot after successful firmware update
    // This callback should never return as the system will restart
    void (*firmware_reboot_cb)(void);

    // Reads firmware data from OTA storage area
    // Called during firmware update to retrieve data chunks from storage
    void (*firmware_read_cb)(void* ctx,
                             uint32_t current_addr,
                             const uint8_t** data,
                             size_t* size);

    // Prepares flash memory for writing (e.g., erasing sectors)
    // Called once before starting the firmware update process
    void (*firmware_prepare_cb)(void* ctx);

    // Writes firmware data to main flash memory
    // Called for each data chunk during firmware update
    void (*firmware_write_cb)(void* ctx,
                              uint32_t flash_addr,
                              const uint8_t* data,
                              size_t size);

    // Client-specific transfer callbacks
    // Stores received data to local storage (e.g., flash memory)
    // Returns: true if successful, false on error
    bool (*transfer_store_cb)(void* ctx,
                              const uint8_t* data,
                              size_t size);

    // Resets the transfer state (e.g., clears storage offset)
    // Called when transfer fails or needs to be restarted
    void (*transfer_reset_cb)(void* ctx);
};

// Internal: Initialize OTA client context
// Returns: 0 on success, negative value on error
int ota_client_init(OTA_client_ctx* ctx);

// Internal: Helper function for handling DATA packets
bool ota_client_handle_data_packet(OTA_client_ctx* ctx,
                                    void* user_ctx,
                                    const uint8_t* buffer,
                                    size_t size);

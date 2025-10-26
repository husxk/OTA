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
    // Firmware update callbacks
    // Firmware callbacks needs to be in RAM in runtime

    // called after flash update to reboot device
    void (*firmware_reboot_cb)(void);

    // called to get data for OTA buffer
    void (*firmware_get_data_cb)(void* ctx,
                                 uint32_t current_addr,
                                 const uint8_t** data,
                                 size_t* size);

    // called before starting firmware write
    // (e.g., to disable interrupts)
    void (*firmware_pre_write_cb)(void* ctx);

    // called to write data to flash
    void (*firmware_write_flash_cb)(void* ctx,
                                    uint32_t flash_addr,
                                    const uint8_t* data,
                                    size_t size);

    // Transfer callbacks

    // called to send data to sender
    void (*transfer_send_data_cb)(void* ctx, const uint8_t* data, size_t size);

    // called to receive data from network
    size_t (*transfer_receive_data_cb)(void* ctx, uint8_t* buffer, size_t max_size);

    // called when transfer error occurs
    void (*transfer_on_error_cb)(void* ctx, const char* error_msg);

    // called when FIN packet is received (transfer complete)
    void (*transfer_complete_cb)(void* ctx, uint32_t total_bytes);

    // Debug/Logging callbacks
    // called to log debug messages
    void (*debug_log_cb)(void* ctx, const char* format, ...);

    // Server-specific callbacks
    // called to get payload data for sending
    bool (*server_get_payload_cb)(void* ctx,
                                  const uint8_t** data,
                                  size_t* size);

    // called after successful DATA-ACK exchange
    void (*server_transfer_progress_cb)(void* ctx, uint32_t bytes_sent, uint32_t packet_number);

    ota_memory_t memory;  // Memory configuration
} ota_config_t;

void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n);

void OTA_setup_memory(ota_config_t* config,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start);

bool OTA_RAM_FUNCTION(OTA_write_firmware)(ota_config_t* config, void* ctx);

bool OTA_handle_data(ota_config_t* config,
                     void* ctx,
                     const uint8_t* buffer,
                     size_t size);

bool OTA_run_server_transfer(ota_config_t* config, void* ctx);

#ifdef __cplusplus
}
#endif

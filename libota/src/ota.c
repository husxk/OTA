#include "ota.h"
#include "packet.h"
#include "protocol.h"
#include <stdarg.h>

void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n)
{
  uint8_t* d = (uint8_t*)dest;
  const uint8_t* s = (const uint8_t*)src;

  for (size_t i = 0; i < n; i++)
  {
      d[i] = s[i];
  }
}

void OTA_setup_memory(ota_config_t* config,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start)
{
    if (!config)
        return;

    config->memory.ota_storage_start = ota_storage_start;
    config->memory.ota_storage_end = ota_storage_end;
    config->memory.flash_start = flash_start;
}

static void ota_debug_log(ota_config_t* config, void* ctx, const char* format, ...)
{
    if (!config || !config->debug_log_cb)
        return;

    va_list args;
    va_start(args, format);
    config->debug_log_cb(ctx, format, args);
    va_end(args);
}

bool OTA_RAM_FUNCTION(OTA_write_firmware)(ota_config_t* config, void* ctx)
{
    if (!config ||
        !config->firmware_reboot_cb ||
        !config->firmware_get_data_cb ||
        !config->firmware_pre_write_cb ||
        !config->firmware_write_flash_cb)
    {
        return false;
    }

    config->firmware_pre_write_cb(ctx);

    uint32_t flash_addr = config->memory.flash_start;
    uint32_t ota_addr = config->memory.ota_storage_start;

    while (ota_addr < config->memory.ota_storage_end)
    {
        // Get data from user callback
        const uint8_t* data;
        size_t size;

        config->firmware_get_data_cb(ctx, ota_addr, &data, &size);

        // Write data to main flash
        config->firmware_write_flash_cb(ctx, flash_addr, data, size);

        ota_addr += size;
        flash_addr += size;
    }

    // Reboot the device
    // Never return from this function
    config->firmware_reboot_cb();

    // This line will never be reached
    return true;
}

static bool ota_send_fin_packet(ota_config_t* config, void* ctx)
{
    uint8_t fin_buffer[OTA_FIN_PACKET_LENGTH];
    size_t fin_size = OTA_packet_write_fin(fin_buffer, sizeof(fin_buffer));
    
    if (fin_size == 0)
    {
        config->transfer_on_error_cb(ctx, "Failed to create FIN packet");
        return false;
    }

    config->transfer_send_data_cb(ctx, fin_buffer, fin_size);
    ota_debug_log(config, ctx, "OTA: FIN packet sent\n");
    return true;
}

static bool ota_send_data_packet(ota_config_t* config, void* ctx, const uint8_t* data, size_t size)
{
    uint8_t send_buffer[OTA_DATA_PACKET_LENGTH];
    size_t bytes_written = OTA_packet_write_data(send_buffer, sizeof(send_buffer), data, size);

    if (bytes_written == 0)
    {
        config->transfer_on_error_cb(ctx, "Failed to create DATA packet");
        return false;
    }

    config->transfer_send_data_cb(ctx, send_buffer, bytes_written);
    ota_debug_log(config, ctx, "OTA: DATA packet sent (%zu bytes)\n", size);
    return true;
}

static bool ota_wait_for_response(ota_config_t* config, void* ctx, uint8_t expected_type)
{
    uint8_t response_buffer[OTA_COMMON_PACKET_LENGTH];
    size_t response_size = config->transfer_receive_data_cb(ctx, response_buffer, sizeof(response_buffer));

    if (response_size == 0)
    {
        config->transfer_on_error_cb(ctx, "No response received");
        return false;
    }

    uint8_t packet_type = OTA_packet_get_type(response_buffer, response_size);
    
    if (packet_type != expected_type)
    {
        if (packet_type == OTA_NACK_TYPE)
        {
            config->transfer_on_error_cb(ctx, "Received NACK");
        }
        else
        {
            config->transfer_on_error_cb(ctx, "Invalid response");
        }

        return false;
    }

    ota_debug_log(config, ctx, "OTA: Received ACK\n");

    return true;
}

bool OTA_run_server_transfer(ota_config_t* config, void* ctx)
{
    if (!config || !ctx)
    {
        return false;
    }

    // Validate required server callbacks
    if (!config->server_get_payload_cb ||
        !config->transfer_send_data_cb ||
        !config->transfer_receive_data_cb ||
        !config->transfer_on_error_cb ||
        !config->transfer_complete_cb ||
        !config->server_transfer_progress_cb)
    {
        ota_debug_log(config, ctx, "OTA: Missing required server callbacks\n");
        return false;
    }

    ota_debug_log(config, ctx, "OTA: Starting server file transfer\n");

    uint32_t packet_number = 1;
    uint32_t total_bytes_sent = 0;

    while (true)
    {
        const uint8_t* data;
        size_t size;
        
        if (!config->server_get_payload_cb(ctx, &data, &size))
        {
            // No more data, send FIN packet
            ota_debug_log(config, ctx, "OTA: No more data, sending FIN packet\n");
            
            if (!ota_send_fin_packet(config, ctx))
            {
                return false;
            }
            
            if (!ota_wait_for_response(config, ctx, OTA_ACK_TYPE))
            {
                return false;
            }

            break;
        }

        if (!ota_send_data_packet(config, ctx, data, size))
        {
            return false;
        }

        if (!ota_wait_for_response(config, ctx, OTA_ACK_TYPE))
        {
            return false;
        }

        total_bytes_sent += size;
        config->server_transfer_progress_cb(ctx, total_bytes_sent, packet_number);

        packet_number++;
    }

    // Transfer completed successfully
    ota_debug_log(config, ctx, "OTA: File transfer completed successfully\n");
    config->transfer_complete_cb(ctx, total_bytes_sent);
    
    return true;
}

bool OTA_handle_data(ota_config_t* config,
                     void* ctx,
                     const uint8_t* buffer,
                     size_t size)
{
    if (!config || !buffer || size == 0)
    {
        ota_debug_log(config, ctx, "OTA: Received empty or invalid packet\n");
        return false;
    }

    // Validate required callbacks
    if (!config->transfer_write_data_cb ||
        !config->transfer_reset_offset_cb ||
        !config->transfer_send_data_cb ||
        !config->transfer_on_error_cb ||
        !config->transfer_complete_cb)
    {
        ota_debug_log(config, ctx, "OTA: Missing required callbacks\n");
        return false;
    }

    // Parse OTA packet
    uint8_t packet_type = OTA_packet_get_type(buffer, size);

    switch (packet_type)
    {
        case OTA_DATA_TYPE:
            ota_debug_log(config, ctx, "OTA: Received DATA packet\n");
            return OTA_handle_data_packet(config, ctx, buffer, size);

        case OTA_ACK_TYPE:
            ota_debug_log(config, ctx, "OTA: Received ACK packet\n");
            return true;

        case OTA_NACK_TYPE:
            ota_debug_log(config, ctx, "OTA: Received NACK packet\n");
            return true;

        case OTA_FIN_TYPE:
            ota_debug_log(config, ctx,
                          "OTA: Received FIN packet, file transfer complete!\n");

            // Send ACK for FIN packet
            uint8_t ack_buffer[OTA_ACK_PACKET_LENGTH];
            size_t ack_size = OTA_packet_write_ack(ack_buffer, sizeof(ack_buffer));
            if (ack_size > 0)
            {
                config->transfer_send_data_cb(ctx, ack_buffer, ack_size);
            }

            // Calculate total bytes transferred
            uint32_t total_bytes = config->memory.ota_storage_end -
                                   config->memory.ota_storage_start;

            // Notify platform that transfer is complete
            config->transfer_complete_cb(ctx, total_bytes);

            return true;

        case OTA_INVALID_TYPE:
        default:
            ota_debug_log(config, ctx,
                          "OTA: Received invalid packet (type: 0x%02X)\n", packet_type);

            // Send NACK for invalid packet
            uint8_t nack_buffer[OTA_NACK_PACKET_LENGTH];
            size_t nack_size = OTA_packet_write_nack(nack_buffer, sizeof(nack_buffer));
            if (nack_size > 0)
            {
                config->transfer_send_data_cb(ctx, nack_buffer, nack_size);
            }
            return false;
    }
}


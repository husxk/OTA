#include "ota_client.h"
#include "ota_common.h"
#include "packet.h"
#include "protocol.h"
#include <stdarg.h>

static void ota_client_handle_error(OTA_client_ctx* ctx,
                                    void* user_ctx,
                                    const char* error_message)
{
    ctx->common.callbacks.transfer_error_cb(user_ctx, error_message);
    ctx->transfer_reset_cb(user_ctx);

    if (!OTA_send_nack_packet(&ctx->common, user_ctx))
    {
        OTA_debug_log(&ctx->common, user_ctx, "OTA: Failed to send NACK packet");
    }
}

void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n)
{
  uint8_t* d = (uint8_t*)dest;
  const uint8_t* s = (const uint8_t*)src;

  for (size_t i = 0; i < n; i++)
  {
      d[i] = s[i];
  }
}

void OTA_client_setup_memory(OTA_client_ctx* ctx,
                             uint32_t ota_storage_start,
                             uint32_t ota_storage_end,
                             uint32_t flash_start)
{
    if (!ctx)
        return;

    ctx->memory.ota_storage_start = ota_storage_start;
    ctx->memory.ota_storage_end = ota_storage_end;
    ctx->memory.flash_start = flash_start;
}

bool OTA_RAM_FUNCTION(OTA_client_write_firmware)(OTA_client_ctx* ctx,
                                                 void* user_ctx)
{
    if (!ctx                      ||
        !ctx->firmware_reboot_cb  ||
        !ctx->firmware_read_cb    ||
        !ctx->firmware_prepare_cb ||
        !ctx->firmware_write_cb)
    {
        return false;
    }

    ctx->firmware_prepare_cb(user_ctx);

    uint32_t flash_addr = ctx->memory.flash_start;
    uint32_t ota_addr   = ctx->memory.ota_storage_start;

    while (ota_addr < ctx->memory.ota_storage_end)
    {
        // Get data from user callback
        const uint8_t* data;
        size_t size;

        ctx->firmware_read_cb(user_ctx, ota_addr, &data, &size);

        // Write data to main flash
        ctx->firmware_write_cb(user_ctx, flash_addr, data, size);

        ota_addr   += size;
        flash_addr += size;
    }

    // Reboot the device
    // Never return from this function
    ctx->firmware_reboot_cb();

    // This line will never be reached
    return true;
}

static bool ota_client_handle_data_packet(OTA_client_ctx* ctx,
                                          void* user_ctx,
                                          const uint8_t* buffer,
                                          size_t size)
{
    // Validate the packet
    const uint8_t* payload = OTA_packet_get_data(buffer, size);

    if (payload == NULL)
    {
        ota_client_handle_error(ctx, user_ctx,
                                "Invalid packet format");
        return false;
    }

    // Write data to storage
    if (!ctx->transfer_store_cb(user_ctx, payload, OTA_DATA_PAYLOAD_SIZE))
    {
        ota_client_handle_error(ctx, user_ctx,
                                "Failed to write data to storage");
        return false;
    }

    // Success, send ACK
    if (!OTA_send_ack_packet(&ctx->common, user_ctx))
    {
        OTA_debug_log(&ctx->common, user_ctx, "OTA: Failed to send ACK packet");
        return false;
    }

    return true;
}

bool OTA_client_handle_data(OTA_client_ctx* ctx,
                             void* user_ctx,
                             const uint8_t* buffer,
                             size_t size)
{
    if (!ctx    ||
        !buffer ||
        size == 0)
    {
        OTA_debug_log(&ctx->common, user_ctx,
                             "OTA: Received empty or invalid packet\n");
        return false;
    }

    if (!ctx->transfer_store_cb                  ||
        !ctx->transfer_reset_cb                  ||
        !ctx->common.callbacks.transfer_send_cb  ||
        !ctx->common.callbacks.transfer_error_cb ||
        !ctx->common.callbacks.transfer_done_cb)
    {
        OTA_debug_log(&ctx->common, user_ctx,
                             "OTA: Missing required callbacks\n");
        return false;
    }

    // Parse OTA packet
    uint8_t packet_type = OTA_packet_get_type(buffer, size);

    switch (packet_type)
    {
        case OTA_DATA_TYPE:
            OTA_debug_log(&ctx->common, user_ctx, "OTA: Received DATA packet\n");

            return ota_client_handle_data_packet(ctx, user_ctx, buffer, size);

        case OTA_ACK_TYPE:
            OTA_debug_log(&ctx->common, user_ctx, "OTA: Received ACK packet\n");

            return true;

        case OTA_NACK_TYPE:
            OTA_debug_log(&ctx->common, user_ctx, "OTA: Received NACK packet\n");

            return true;

        case OTA_FIN_TYPE:
            OTA_debug_log(&ctx->common, user_ctx,
                                "OTA: Received FIN packet, file transfer complete!\n");

            // Send ACK for FIN packet
            if (!OTA_send_ack_packet(&ctx->common, user_ctx))
            {
                OTA_debug_log(&ctx->common, user_ctx,
                              "OTA: Failed to send ACK for FIN packet");
            }

            // Calculate total bytes transferred
            uint32_t total_bytes = ctx->memory.ota_storage_end -
                                   ctx->memory.ota_storage_start;

            // Notify platform that transfer is complete
            ctx->common.callbacks.transfer_done_cb(user_ctx, total_bytes);

            return true;

        case OTA_INVALID_TYPE:
        default:
            OTA_debug_log(&ctx->common, user_ctx,
                               "OTA: Received invalid packet (type: 0x%02X)\n",
                               packet_type);

            // Send NACK for invalid packet
            if (!OTA_send_nack_packet(&ctx->common, user_ctx))
            {
                OTA_debug_log(&ctx->common, user_ctx,
                              "OTA: Failed to send NACK for invalid packet");
            }

            return false;
    }
}


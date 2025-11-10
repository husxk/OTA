#include "ota_server.h"
#include "ota_common.h"
#include "packet.h"
#include "protocol.h"
#include <stdarg.h>

static bool ota_send_fin_packet_server(OTA_server_ctx* ctx,
                                       void* user_ctx)
{
    uint8_t fin_buffer[OTA_FIN_PACKET_LENGTH];
    size_t fin_size = OTA_packet_write_fin(fin_buffer,
                                           sizeof(fin_buffer));

    if (fin_size == 0)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Failed to create FIN packet");
        return false;
    }

    ctx->common.callbacks.transfer_send_cb(user_ctx, fin_buffer, fin_size);
    OTA_common_debug_log(&ctx->common, user_ctx,
                         "OTA: FIN packet sent\n");
    return true;
}

static bool ota_send_data_packet_server(OTA_server_ctx* ctx,
                                        void* user_ctx,
                                        const uint8_t* data,
                                        size_t size)
{
    uint8_t send_buffer[OTA_DATA_PACKET_LENGTH];
    size_t bytes_written =
        OTA_packet_write_data(send_buffer,
                              sizeof(send_buffer),
                              data,
                              size);

    if (bytes_written == 0)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Failed to create DATA packet");
        return false;
    }

    ctx->common.callbacks.transfer_send_cb(user_ctx, send_buffer, bytes_written);
    OTA_common_debug_log(&ctx->common, user_ctx,
                         "OTA: DATA packet sent (%zu bytes)\n", size);
    return true;
}

static bool ota_wait_for_response_server(OTA_server_ctx* ctx,
                                         void* user_ctx,
                                         uint8_t expected_type)
{
    uint8_t response_buffer[OTA_COMMON_PACKET_LENGTH];

    size_t response_size =
        ctx->common.callbacks.transfer_receive_cb(user_ctx,
                                                  response_buffer,
                                                  sizeof(response_buffer));

    if (response_size == 0)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "No response received");
        return false;
    }

    uint8_t packet_type = OTA_packet_get_type(response_buffer, response_size);

    if (packet_type != expected_type)
    {
        if (packet_type == OTA_NACK_TYPE)
        {
            ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                    "Received NACK");
        }
        else
        {
            ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                    "Invalid response");
        }

        return false;
    }

    OTA_common_debug_log(&ctx->common, user_ctx,
                         "OTA: Received %u\n", packet_type);

    return true;
}

bool OTA_server_run_transfer(OTA_server_ctx* ctx, void* user_ctx)
{
    if (!ctx || !user_ctx)
    {
        return false;
    }

    // Validate required server callbacks
    if (!ctx->server_get_payload_cb                ||
        !ctx->common.callbacks.transfer_send_cb    ||
        !ctx->common.callbacks.transfer_receive_cb ||
        !ctx->common.callbacks.transfer_error_cb   ||
        !ctx->common.callbacks.transfer_done_cb    ||
        !ctx->server_transfer_progress_cb)
    {
        OTA_common_debug_log(&ctx->common, user_ctx,
                             "OTA: Missing required server callbacks\n");
        return false;
    }

    OTA_common_debug_log(&ctx->common, user_ctx,
                         "OTA: Starting server file transfer\n");

    uint32_t packet_number = 1;
    uint32_t total_bytes_sent = 0;

    while (true)
    {
        const uint8_t* data;
        size_t size;

        if (!ctx->server_get_payload_cb(user_ctx, &data, &size))
        {
            // No more data, send FIN packet
            OTA_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: No more data, sending FIN packet\n");

            if (!ota_send_fin_packet_server(ctx, user_ctx))
            {
                return false;
            }

            if (!ota_wait_for_response_server(ctx, user_ctx, OTA_ACK_TYPE))
            {
                return false;
            }

            break;
        }

        if (!ota_send_data_packet_server(ctx, user_ctx, data, size))
        {
            return false;
        }

        if (!ota_wait_for_response_server(ctx, user_ctx, OTA_ACK_TYPE))
        {
            return false;
        }

        total_bytes_sent += size;
        ctx->server_transfer_progress_cb(user_ctx,
                                         total_bytes_sent,
                                         packet_number);

        packet_number++;
    }

    // Transfer completed successfully
    OTA_common_debug_log(&ctx->common, user_ctx,
                         "OTA: File transfer completed successfully\n");
    ctx->common.callbacks.transfer_done_cb(user_ctx, total_bytes_sent);

    return true;
}

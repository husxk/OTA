#include "libota/ota_server.h"
#include "internal/ota_server_internal.h"
#include "internal/ota_common_internal.h"
#include "internal/packet.h"
#include "libota/protocol.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <stdarg.h>
#include <stdlib.h>

static bool ota_server_wait_for_response(OTA_server_ctx* ctx,
                                         void* user_ctx,
                                         uint8_t expected_type)
{
    uint8_t response_buffer[OTA_COMMON_PACKET_LENGTH];
    size_t response_size = 0;

    // Retry loop for TLS I/O
    // TLS may need multiple read attempts
    // when MBEDTLS_ERR_SSL_WANT_READ/WRITE is returned

    // TODO: Do we even need this loop? Shouldnt we fix APi
    // to get error msg from lower level and handle it correcttly?
    // TODO: switch this to time based timeout
    const int max_retries = 1000; // Reasonable limit to avoid infinite loop
    int retry_count = 0;

    while (response_size == 0 &&
           retry_count < max_retries)
    {
        response_size = ota_recv_data(&ctx->common, user_ctx,
                                      response_buffer,
                                      sizeof(response_buffer));

        // If we got data, break out of retry loop
        if (response_size > 0)
            break;

        retry_count++;
    }

    if (response_size == 0)
    {
        ota_common_transfer_error(&ctx->common, user_ctx,
                                  "No response received: timeout");
        return false;
    }

    uint8_t packet_type = ota_packet_get_type(response_buffer, response_size);

    if (packet_type != expected_type)
    {
        if (packet_type == OTA_NACK_TYPE)
        {
            ota_common_transfer_error(&ctx->common, user_ctx,
                                      "Transfer rejected by client (NACK)");
        }
        else
        {
            ota_common_transfer_error(&ctx->common, user_ctx,
                                      "Invalid response");
        }

        return false;
    }

    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: Received %u\n", packet_type);

    return true;
}

bool OTA_server_run_transfer(OTA_server_ctx* ctx, void* user_ctx)
{
    if (!ctx || !user_ctx)
    {
        return false;
    }

    // TODO: we shouldnt call it directly, it should be handled
    // by reading/writting functions from ota_common
    //
    // Perform TLS handshake (blocking mode)
    if (ctx->common.tls_enabled)
    {
        if (!ota_common_tls_handshake(&ctx->common, user_ctx, true))
        {
            return false;
        }
    }

    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: Starting server file transfer\n");

    // Initialize SHA-512
    if (ota_common_sha512_init(&ctx->common) != 0)
    {
        ota_common_debug_log(&ctx->common, user_ctx,
                             "Warning: Failed to initialize SHA-512, "
                             "continuing without hash calculation\n");
    }

    uint32_t packet_number = 1;
    uint32_t total_bytes_sent = 0;

    while (true)
    {
        const uint8_t* data;
        size_t size;

        if (!ctx->server_get_payload_cb(user_ctx, &data, &size))
        {
            // No more data, finalize SHA-512 hash before sending FIN
            ota_common_sha512_finish(&ctx->common);

            // Sign the hash if private key is available
            ota_common_sha512_sign(&ctx->common);

            // No more data, send FIN packet
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: No more data, sending FIN packet\n");

            if (!ota_send_fin_packet(&ctx->common, user_ctx))
            {
                return false;
            }

            if (!ota_server_wait_for_response(ctx, user_ctx, OTA_ACK_TYPE))
            {
                return false;
            }

            break;
        }

        // Update SHA-512 hash with data chunk (before sending)
        ota_common_sha512_update(&ctx->common, data, size);

        if (!ota_send_data_packet(&ctx->common, user_ctx, data, size))
        {
            return false;
        }

        if (!ota_server_wait_for_response(ctx, user_ctx, OTA_ACK_TYPE))
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
    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: File transfer completed successfully\n");
    ctx->common.callbacks.transfer_done_cb(user_ctx, total_bytes_sent);

    // Close TLS connection gracefully
    ota_tls_close(&ctx->common);

    return true;
}

int OTA_server_cleanup(OTA_server_ctx* ctx)
{
    if (!ctx)
        return -1;

    return ota_common_cleanup(&ctx->common);
}

void OTA_server_destroy(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return;
    }

    // Cleanup resources (TLS, SHA-512, etc.)
    ota_common_cleanup(&ctx->common);

    // Free the context itself
    free(ctx);
}

int OTA_server_reset(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    // Cleanup runtime state (TLS connections, SHA-512 operations)
    // This preserves callbacks and configuration
    return ota_common_cleanup(&ctx->common);
}

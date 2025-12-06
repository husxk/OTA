#include "ota_server.h"
#include "ota_common.h"
#include "tls_context.h"
#include "packet.h"
#include "protocol.h"
#include <mbedtls/error.h>
#include <stdarg.h>

static bool ota_send_fin_packet_server(OTA_server_ctx* ctx,
                                       void* user_ctx)
{
    uint8_t fin_buffer[OTA_FIN_PACKET_LENGTH];

    // Check if signature is available and has correct length
    if (!ctx->common.sha512.sha512_signed)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Cannot send FIN packet: "
                                                "signature not calculated");
        return false;
    }

    if (ctx->common.sha512.sha512_signature_length != OTA_SHA512_SIGNATURE_LENGTH)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Cannot send FIN packet: "
                                                "invalid signature length");
        return false;
    }

    size_t fin_size = OTA_packet_write_fin(fin_buffer,
                                           sizeof(fin_buffer),
                                           ctx->common.sha512.sha512_signature,
                                           ctx->common.sha512.sha512_signature_length);

    if (fin_size == 0)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Failed to create FIN packet");
        return false;
    }

    OTA_send_data(&ctx->common, user_ctx, fin_buffer, fin_size);
    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: FIN packet sent with signature\n");
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

    OTA_send_data(&ctx->common, user_ctx, send_buffer, bytes_written);
    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: DATA packet sent (%zu bytes)\n", size);
    return true;
}

static bool ota_wait_for_response_server(OTA_server_ctx* ctx,
                                         void* user_ctx,
                                         uint8_t expected_type)
{
    uint8_t response_buffer[OTA_COMMON_PACKET_LENGTH];
    size_t response_size = 0;

    // Retry loop for TLS I/O
    // TLS may need multiple read attempts
    // when MBEDTLS_ERR_SSL_WANT_READ/WRITE is returned

    // TODO: switch this to time based timeout
    const int max_retries = 1000; // Reasonable limit to avoid infinite loop
    int retry_count = 0;

    while (response_size == 0 &&
           retry_count < max_retries)
    {
        response_size = OTA_recv_data(&ctx->common, user_ctx,
                                      response_buffer,
                                      sizeof(response_buffer));

        // If we got data, break out of retry loop
        if (response_size > 0)
            break;

        retry_count++;
    }

    if (response_size == 0)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "No response received: timeout");
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

    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: Received %u\n", packet_type);

    return true;
}

// Perform TLS handshake
// Returns: true on success, false on error
static bool ota_server_handshake(OTA_server_ctx* ctx, void* user_ctx)
{
    if (!ctx ||
        !user_ctx)
    {
        return false;
    }

    // Set user context for TLS
    ctx->common.tls.user_ctx = user_ctx;

    // Perform TLS handshake
    // Server needs to complete handshake before starting transfer
    int ret;

    while ((ret = tls_context_handshake(&ctx->common.tls)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ctx->common.callbacks.transfer_error_cb(user_ctx, "TLS handshake failed");
            return false;
        }
    }

    return true;
}

int OTA_server_init(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    // Check if PKI data is set
    if (!tls_is_pki_data_set(&ctx->common.tls))
    {
        ota_common_debug_log(&ctx->common, NULL,
                             "Error: PKI data not set. "
                             "Call OTA_set_pki_data() first\n");
        return -1;
    }

    // Use common TLS initialization function
    return ota_common_tls_init(&ctx->common, MBEDTLS_SSL_IS_SERVER);
}

bool OTA_server_run_transfer(OTA_server_ctx* ctx, void* user_ctx)
{
    if (!ctx ||
        !user_ctx)
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
        ota_common_debug_log(&ctx->common, user_ctx,
                             "OTA: Missing required server callbacks\n");
        return false;
    }

    // Perform TLS handshake
    if (!ota_server_handshake(ctx, user_ctx))
    {
        return false;
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

        // Update SHA-512 hash with data chunk (before sending)
        ota_common_sha512_update(&ctx->common, data, size);

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
    ota_common_debug_log(&ctx->common, user_ctx,
                         "OTA: File transfer completed successfully\n");
    ctx->common.callbacks.transfer_done_cb(user_ctx, total_bytes_sent);

    // Close TLS connection gracefully
    tls_context_close(&ctx->common.tls);

    return true;
}

int OTA_server_cleanup(OTA_server_ctx* ctx)
{
    if (!ctx)
        return -1;

    // Use common TLS cleanup function
    return ota_common_tls_cleanup(&ctx->common);
}

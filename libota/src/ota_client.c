#include "ota_client.h"
#include "ota_common.h"
#include "tls_context.h"
#include "packet.h"
#include "protocol.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
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

int OTA_client_init(OTA_client_ctx* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    // Initialize SHA-512 hash calculation for image verification
    if (ota_common_sha512_init(&ctx->common) != 0)
    {
        ota_common_debug_log(&ctx->common, NULL,
                             "Warning: Failed to initialize SHA-512, "
                             "continuing without hash calculation\n");
    }

    return ota_common_tls_init(&ctx->common, MBEDTLS_SSL_IS_CLIENT);
}

int OTA_client_cleanup(OTA_client_ctx* ctx)
{
    if (!ctx)
        return -1;

    return ota_common_tls_cleanup(&ctx->common);
}

int OTA_client_handshake(OTA_client_ctx* ctx)
{
    if (!ctx ||
        !ctx->common.tls.initialized)
    {
        return -1;
    }

    return tls_context_handshake(&ctx->common.tls);
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
    uint32_t ota_addr = ctx->memory.ota_storage_start;

    while (ota_addr < ctx->memory.ota_storage_end)
    {
        // Get data from user callback
        const uint8_t* data;
        size_t size;

        ctx->firmware_read_cb(user_ctx, ota_addr, &data, &size);

        // Write data to main flash
        ctx->firmware_write_cb(user_ctx, flash_addr, data, size);

        ota_addr += size;
        flash_addr += size;
    }

    // Reboot the device
    // Never return from this function
    ctx->firmware_reboot_cb();

    // This line will never be reached
    return true;
}

static bool OTA_client_handle_data_packet(OTA_client_ctx* ctx,
                                          void* user_ctx,
                                          const uint8_t* buffer,
                                          size_t size)
{
    if (!ctx                                     ||
        !ctx->transfer_store_cb                  ||
        !ctx->transfer_reset_cb                  ||
        !ctx->common.callbacks.transfer_send_cb  ||
        !ctx->common.callbacks.transfer_error_cb)
    {
        return false;
    }

    // Validate the packet
    const uint8_t* payload = OTA_packet_get_data(buffer, size);
    if (payload == NULL)
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx, "Invalid packet format");
        ctx->transfer_reset_cb(user_ctx);
        ota_send_nack_packet(&ctx->common, user_ctx);
        return false;
    }

    // Update SHA-512 hash with payload data (before storing)
    ota_common_sha512_update(&ctx->common, payload, OTA_DATA_PAYLOAD_SIZE);

    // Write data to storage
    if (!ctx->transfer_store_cb(user_ctx, payload, OTA_DATA_PAYLOAD_SIZE))
    {
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "Failed to write data to storage");
        ctx->transfer_reset_cb(user_ctx);
        ota_send_nack_packet(&ctx->common, user_ctx);
        return false;
    }

    // Success, send ACK
    ota_send_ack_packet(&ctx->common, user_ctx);
    return true;
}

// Perform TLS handshake
// Returns: true on success (handshake complete or in progress),
//          false on error
static bool ota_client_handshake(OTA_client_ctx* ctx, void* user_ctx)
{
    if (!ctx ||
        !ctx->common.tls.initialized)
    {
        return true; // No TLS, nothing to do
    }

    // Set user context for TLS callbacks
    ctx->common.tls.user_ctx = user_ctx;

    // Check if handshake is already complete
    if (tls_context_handshake_complete(&ctx->common.tls))
    {
        return true;
    }

    ota_common_debug_log(&ctx->common, user_ctx,
                         "Handshake not complete, continuing...\n");

    int ret = tls_context_handshake(&ctx->common.tls);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // Handshake needs more I/O.
        // Application should call this again when more data is available

        ota_common_debug_log(&ctx->common, user_ctx,
                             "Handshake needs more I/O (WANT_%s)\n",
                             (ret == MBEDTLS_ERR_SSL_WANT_READ) ?
                             "READ" : "WRITE");
        return true;
    }
    else if (ret != 0)
    {
        // Handshake error
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(&ctx->common, user_ctx,
                             "Handshake error: %d (%s)\n",
                             ret, error_buf);
        ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                "TLS handshake failed");
        return false;
    }

    // handshake completed
    ota_common_debug_log(&ctx->common, user_ctx,
                         "Handshake completed successfully!\n");
    return true;
}

// Read decrypted data from TLS connection
// Returns: true on success, false on error
//          output_size will be set to number of bytes read
static bool ota_client_read_tls(OTA_client_ctx* ctx,
                                void* user_ctx,
                                uint8_t* output_buffer,
                                size_t output_buffer_size,
                                size_t* output_size)
{
    if (!ctx                         ||
        !ctx->common.tls.initialized ||
        !output_buffer               ||
        !output_size)
    {
        if (output_size)
            *output_size = 0;

        return true; // No TLS or invalid params, nothing to read
    }

    // Check if handshake is complete before reading data
    if (!tls_context_handshake_complete(&ctx->common.tls))
    {
        *output_size = 0;
        return true;
    }

    size_t decrypted_size = OTA_recv_data(&ctx->common, user_ctx,
                                           output_buffer,
                                           output_buffer_size);

    if (decrypted_size == 0)
    {
        // No data available yet
        ota_common_debug_log(&ctx->common, user_ctx,
                             "No decrypted data available yet\n");
        *output_size = 0;
        return true;
    }

    ota_common_debug_log(&ctx->common, user_ctx,
                         "Read %zu bytes of decrypted data\n",
                         decrypted_size);

    *output_size = decrypted_size;
    return true;
}

// Handle TLS handshake and read decrypted data if TLS is active
// Returns: true if data is ready in output_buffer/output_size, false on error,
//          true with output_size=0 if more I/O needed (WANT_READ/WANT_WRITE)
static bool ota_client_handle_tls(OTA_client_ctx* ctx,
                                  void* user_ctx,
                                  uint8_t* output_buffer,
                                  size_t output_buffer_size,
                                  size_t* output_size)
{
    if (!ctx ||
        !ctx->common.tls.initialized)
    {
        *output_size = 0;
        return true; // No TLS, caller should use raw buffer
    }

    // Perform TLS handshake
    if (!ota_client_handshake(ctx, user_ctx))
    {
        return false;
    }

    // Read decrypted data from TLS
    return ota_client_read_tls(ctx, user_ctx, output_buffer,
                               output_buffer_size, output_size);
}

bool OTA_client_handle_data(OTA_client_ctx* ctx,
                            void* user_ctx,
                            const uint8_t* buffer,
                            size_t size)
{
    if (!ctx)
    {
        return false;
    }

    // Validate required callbacks
    if (!ctx->transfer_store_cb                    ||
        !ctx->transfer_reset_cb                    ||
        !ctx->common.callbacks.transfer_send_cb    ||
        !ctx->common.callbacks.transfer_receive_cb ||
        !ctx->common.callbacks.transfer_error_cb   ||
        !ctx->common.callbacks.transfer_done_cb)
    {
        ota_common_debug_log(&ctx->common, user_ctx,
                            "OTA: Missing required callbacks\n");
        return false;
    }

    // Handle TLS handshake and read decrypted data if TLS is active
    // Use maximum packet size (DATA packet is the largest at 258 bytes)
    uint8_t decrypted_buffer[OTA_DATA_PACKET_LENGTH];
    size_t decrypted_size = 0;

    if (ctx->common.tls.initialized)
    {
        ota_common_debug_log(&ctx->common, user_ctx,
                             "TLS is initialized, handling TLS...\n");

        // handle handshake and read decrypted data
        if (!ota_client_handle_tls(ctx, user_ctx, decrypted_buffer,
                                   sizeof(decrypted_buffer),
                                   &decrypted_size))
        {
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "TLS handling failed\n");
            return false;
        }

        if (decrypted_size == 0)
        {
            return true;
        }

        // Use decrypted data
        buffer = decrypted_buffer;
        size   = decrypted_size;
    }
    else
    {
        // No TLS, process raw data directly
        if (!buffer ||
            size == 0)
        {
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received empty or invalid packet\n");
            return false;
        }
    }

    if (size == 0)
    {
        ota_common_debug_log(&ctx->common, user_ctx,
                             "ERROR: Buffer size is 0!\n");
        return false;
    }

    if (size < 3)
    {
        ota_common_debug_log(&ctx->common, user_ctx,
                             "ERROR: Buffer too small "
                             "(%zu bytes, need at least 3)\n",
                             size);
        return false;
    }

    uint8_t packet_type = OTA_packet_get_type(buffer, size);

    switch (packet_type)
    {
        case OTA_DATA_TYPE:
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received DATA packet\n");
            return OTA_client_handle_data_packet(ctx, user_ctx, buffer, size);

        case OTA_ACK_TYPE:
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received ACK packet\n");
            return true;

        case OTA_NACK_TYPE:
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received NACK packet\n");
            return true;

        case OTA_FIN_TYPE:
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received FIN packet, file transfer complete!\n");

            // Finalize SHA-512 hash calculation
            if (ctx->common.sha512.sha512_active)
            {
                ota_common_sha512_finish(&ctx->common);
            }

            // Extract signature from FIN packet
            size_t received_signature_len = 0;
            const uint8_t* received_signature =
                OTA_packet_get_fin_signature(buffer,
                                             size,
                                             &received_signature_len);

            if (!received_signature ||
                 received_signature_len != OTA_SHA512_SIGNATURE_LENGTH)
            {
                ota_common_debug_log(&ctx->common, user_ctx,
                                     "OTA: Invalid FIN packet signature format\n");
                // Reset offsets on invalid signature format
                if (ctx->transfer_reset_cb)
                {
                    ctx->transfer_reset_cb(user_ctx);
                }
                ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                        "Invalid FIN packet signature");
                return false;
            }

            // Verify signature using common function
            int verify_ret = ota_common_sha512_verify(&ctx->common,
                                                       received_signature,
                                                       received_signature_len);

            if (verify_ret != 0)
            {
                // Reset offsets on verification failure
                if (ctx->transfer_reset_cb)
                {
                    ctx->transfer_reset_cb(user_ctx);
                }
                ctx->common.callbacks.transfer_error_cb(user_ctx,
                                                        "Signature verification failed");
                return false;
            }

            // Send ACK for FIN packet
            ota_send_ack_packet(&ctx->common, user_ctx);

            // Notify platform that transfer is complete
            ctx->common.callbacks.transfer_done_cb(user_ctx, 0);

            return true;

        case OTA_INVALID_TYPE:
        default:
            ota_common_debug_log(&ctx->common, user_ctx,
                                 "OTA: Received invalid packet (type: 0x%02X)\n",
                                 packet_type);

            // Reset offsets on invalid packet
            if (ctx->transfer_reset_cb)
            {
                ctx->transfer_reset_cb(user_ctx);
            }

            // Send NACK for invalid packet
            ota_send_nack_packet(&ctx->common, user_ctx);

            return false;
    }
}


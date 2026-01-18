#include "internal/ota_client_internal.h"
#include "internal/ota_common_internal.h"
#include "internal/packet.h"
#include "libota/protocol.h"
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stdint.h>

int ota_client_init(OTA_client_ctx* ctx)
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

    // Only initialize TLS if it's enabled
    if (ctx->common.tls_enabled)
    {
        // Set endpoint type for client
        if (ota_tls_set_endpoint(&ctx->common, MBEDTLS_SSL_IS_CLIENT) != 0)
        {
            return -1;
        }

        return ota_common_tls_init(&ctx->common);
    }

    // TLS not enabled, skip initialization
    return 0;
}

bool ota_client_handle_data_packet(OTA_client_ctx* ctx,
                                    void* user_ctx,
                                    const uint8_t* buffer,
                                    size_t size)
{
    if (!ctx)
    {
        return false;
    }

    // Validate the packet
    const uint8_t* payload = ota_packet_get_data(buffer, size);
    if (payload == NULL)
    {
        ota_common_transfer_error(&ctx->common, user_ctx, "Invalid packet format");
        ctx->transfer_reset_cb(user_ctx);
        ota_send_nack_packet(&ctx->common, user_ctx);
        return false;
    }

    // Update SHA-512 hash with payload data (before storing)
    ota_common_sha512_update(&ctx->common, payload, OTA_DATA_PAYLOAD_SIZE);

    // Write data to storage
    if (!ctx->transfer_store_cb(user_ctx, payload, OTA_DATA_PAYLOAD_SIZE))
    {
        ota_common_transfer_error(&ctx->common, user_ctx,
                                  "Failed to write data to storage");
        ctx->transfer_reset_cb(user_ctx);
        ota_send_nack_packet(&ctx->common, user_ctx);
        return false;
    }

    // Success, send ACK
    ota_send_ack_packet(&ctx->common, user_ctx);
    return true;
}

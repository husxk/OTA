#include "internal/ota_server_internal.h"
#include "internal/packet.h"
#include "libota/protocol.h"
#include "libota/ota_common.h"
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stdint.h>

int ota_server_init(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    // Only initialize TLS if it's enabled
    if (ctx->common.tls_enabled)
    {
        // Check if PKI data is set (required for TLS server)
        if (!ota_tls_is_pki_data_set(&ctx->common))
        {
            ota_common_debug_log(&ctx->common, NULL,
                                 "Error: PKI data not set. "
                                 "Call OTA_set_pki_data() first\n");
            return -1;
        }

        // Set endpoint type for server
        if (ota_tls_set_endpoint(&ctx->common, MBEDTLS_SSL_IS_SERVER) != 0)
        {
            return -1;
        }

        // Use common TLS initialization function
        return ota_common_tls_init(&ctx->common);
    }

    // TLS not enabled, skip initialization
    return 0;
}

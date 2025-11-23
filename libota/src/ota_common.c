#include "ota_common.h"
#include "tls_context.h"
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <stdarg.h>

void ota_common_debug_log(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const char* format,
                          ...)
{
    if (!ctx ||
        !ctx->callbacks.debug_log_cb)
    {
        return;
    }

    va_list args;
    va_start(args, format);
    ctx->callbacks.debug_log_cb(user_ctx, format, args);
    va_end(args);
}

void OTA_send_data(OTA_common_ctx_t* ctx,
                   void* user_ctx,
                   const uint8_t* data,
                   size_t size)
{
    if (!ctx  ||
        !data ||
        size == 0)
    {
        return;
    }

    // Use TLS if available, otherwise use plain callback
    if (ctx->tls.initialized)
    {
        tls_context_send(&ctx->tls, data, size);
    }
    else if (ctx->callbacks.transfer_send_cb)
    {
        ctx->callbacks.transfer_send_cb(user_ctx, data, size);
    }
}

size_t OTA_recv_data(OTA_common_ctx_t* ctx,
                     void* user_ctx,
                     uint8_t* buffer,
                     size_t max_size)
{
    if (!ctx    ||
        !buffer ||
        max_size == 0)
    {
        return 0;
    }

    // Use TLS if available, otherwise use plain callback
    if (ctx->tls.initialized)
    {
        int ret = tls_context_receive(&ctx->tls, buffer, max_size);

        if (ret < 0)
            return 0;

        return (size_t)ret;
    }
    else if (ctx->callbacks.transfer_receive_cb)
    {
        return ctx->callbacks.transfer_receive_cb(user_ctx, buffer, max_size);
    }

    return 0;
}

int OTA_set_entropy_cb(tls_entropy_cb_t entropy_cb, void* entropy_ctx)
{
    return tls_set_entropy_callback(entropy_cb, entropy_ctx);
}

int OTA_set_pki_data(tls_context_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len)
{
    return tls_set_pki_data(ctx, cert_data, cert_len, key_data, key_len);
}

int ota_common_tls_init(OTA_common_ctx_t* ctx, int endpoint)
{
    if (!ctx)
        return -1;

    if (!tls_is_entropy_callback_set())
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Entropy callback not set. "
                             "Call OTA_set_entropy_cb() first\n");
        return -1;
    }

    ctx->tls.ota_ctx = ctx;
    ctx->tls.user_ctx = NULL; // Will be set when transfer starts

    ota_common_debug_log(ctx, NULL,
                         "Initializing TLS context...\n");

    int ret = tls_context_init(&ctx->tls, endpoint);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx, NULL,
                             "Error: tls_context_init() failed: "
                             "%d (%s)\n",
                             ret, error_buf);
        return ret;
    }

    ota_common_debug_log(ctx, NULL,
                         "TLS context initialized successfully\n");

    return 0;
}

int ota_common_tls_cleanup(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Close and free TLS context
    tls_context_close(&ctx->tls);
    tls_context_free(&ctx->tls);

    return 0;
}

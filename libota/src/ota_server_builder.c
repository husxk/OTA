#include "libota/ota_server_builder.h"
#include "internal/ota_server_internal.h"
#include "libota/ota_common.h"
#include "libota/tls_context.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Internal builder structure
struct ota_server_builder
{
    // Common callbacks (shared with client)
    OTA_common_callbacks_t common_callbacks;

    // Server-specific callbacks
    OTA_server_callbacks_t server_callbacks;

    // TLS configuration
    bool tls_enabled;
    tls_entropy_cb_t entropy_cb;
    void* entropy_ctx;

    // PKI data for TLS (certificate + private key)
    unsigned char* pki_cert_data;
    size_t pki_cert_len;
    unsigned char* pki_key_data;
    size_t pki_key_len;

    // SHA-512 private key for signing
    unsigned char* sha512_private_key_data;
    size_t sha512_private_key_len;
};

OTA_server_builder_t* OTA_server_builder_create(void)
{
    OTA_server_builder_t* builder = malloc(sizeof(OTA_server_builder_t));
    if (!builder)
    {
        return NULL;
    }

    memset(builder, 0, sizeof(OTA_server_builder_t));
    builder->tls_enabled = false;
    return builder;
}

void OTA_server_builder_destroy(OTA_server_builder_t* builder)
{
    if (builder)
    {
        // Free PKI data if allocated
        if (builder->pki_cert_data)
        {
            free(builder->pki_cert_data);
        }
        if (builder->pki_key_data)
        {
            free(builder->pki_key_data);
        }

        // Free SHA-512 private key data if allocated
        if (builder->sha512_private_key_data)
        {
            free(builder->sha512_private_key_data);
        }

        free(builder);
    }
}

OTA_server_ctx*
OTA_server_builder_build(OTA_server_builder_t* builder, int* error_code)
{
    // Set default error code
    if (error_code)
    {
        *error_code = OTA_SERVER_BUILDER_SUCCESS;
    }

    // Validate builder is not NULL
    if (!builder)
    {
        if (error_code)
        {
            *error_code = OTA_SERVER_BUILDER_ERROR_NULL;
        }
        return NULL;
    }

    // Validate required callbacks
    if (!ota_common_callbacks_validate(&builder->common_callbacks) ||
        !builder->server_callbacks.server_get_payload_cb ||
        !builder->server_callbacks.server_transfer_progress_cb)
    {
        if (error_code)
        {
            *error_code = OTA_SERVER_BUILDER_ERROR_MISSING_CB;
        }
        return NULL;
    }

    // Allocate context
    OTA_server_ctx* ctx = malloc(sizeof(OTA_server_ctx));
    if (!ctx)
    {
        if (error_code)
        {
            *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
        }
        return NULL;
    }

    // Zero-initialize context
    memset(ctx, 0, sizeof(OTA_server_ctx));

    // Copy common callbacks from builder to context
    ota_common_callbacks_copy(&ctx->common.callbacks,
                              &builder->common_callbacks);

    // Copy server-specific callbacks from builder to context
    ctx->server_get_payload_cb       = builder->server_callbacks.server_get_payload_cb;
    ctx->server_transfer_progress_cb = builder->server_callbacks.server_transfer_progress_cb;

    // Set entropy callback if provided (must be done before TLS init)
    if (builder->entropy_cb)
    {
        if (OTA_set_entropy_cb(builder->entropy_cb, builder->entropy_ctx) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Set SHA-512 private key if provided
    if (builder->sha512_private_key_data)
    {
        if (OTA_set_sha512_private_key(&ctx->common,
                                       builder->sha512_private_key_data,
                                       builder->sha512_private_key_len) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Enable TLS if requested
    if (builder->tls_enabled)
    {
        // Validate PKI data is set (required for TLS server)
        if (!builder->pki_cert_data || !builder->pki_key_data)
        {
            if (error_code)
            {
                *error_code = OTA_SERVER_BUILDER_ERROR_MISSING_CB;
            }
            free(ctx);
            return NULL;
        }

        // Set PKI data for TLS
        if (OTA_set_pki_data(&ctx->common,
                            builder->pki_cert_data,
                            builder->pki_cert_len,
                            builder->pki_key_data,
                            builder->pki_key_len) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }

        // Enable TLS
        if (OTA_enable_tls(&ctx->common) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Initialize server context (includes TLS init if enabled)
    if (OTA_server_init(ctx) != 0)
    {
        if (error_code)
        {
            *error_code = OTA_SERVER_BUILDER_ERROR_ALLOC;
        }
        free(ctx);
        return NULL;
    }

    // Context is fully initialized and ready to use
    return ctx;
}

// Common callback setters
void
OTA_server_builder_set_transfer_send_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const uint8_t* data,
                                                   size_t size))
{
    if (builder)
    {
        builder->common_callbacks.transfer_send_cb = cb;
    }
}

void
OTA_server_builder_set_transfer_receive_cb(OTA_server_builder_t* builder,
                                           size_t (*cb)(void* ctx,
                                                        uint8_t* buffer,
                                                        size_t max_size))
{
    if (builder)
    {
        builder->common_callbacks.transfer_receive_cb = cb;
    }
}

void
OTA_server_builder_set_transfer_error_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const char* error_msg))
{
    if (builder)
    {
        builder->common_callbacks.transfer_error_cb = cb;
    }
}

void
OTA_server_builder_set_transfer_done_cb(OTA_server_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   uint32_t total_bytes))
{
    if (builder)
    {
        builder->common_callbacks.transfer_done_cb = cb;
    }
}

void
OTA_server_builder_set_debug_log_cb(OTA_server_builder_t* builder,
                                    void (*cb)(void* ctx,
                                               const char* format,
                                               va_list args))
{
    if (builder)
    {
        builder->common_callbacks.debug_log_cb = cb;
    }
}

// Server-specific callback setters
void
OTA_server_builder_set_server_get_payload_cb(OTA_server_builder_t* builder,
                                            bool (*cb)(void* ctx,
                                                       const uint8_t** data,
                                                       size_t* size))
{
    if (builder)
    {
        builder->server_callbacks.server_get_payload_cb = cb;
    }
}

void
OTA_server_builder_set_server_transfer_progress_cb(OTA_server_builder_t* builder,
                                                    void (*cb)(void* ctx,
                                                               uint32_t bytes_sent,
                                                               uint32_t packet_number))
{
    if (builder)
    {
        builder->server_callbacks.server_transfer_progress_cb = cb;
    }
}

// Configuration setters
int
OTA_server_builder_set_entropy_cb(OTA_server_builder_t* builder,
                                  tls_entropy_cb_t entropy_cb,
                                  void* entropy_ctx)
{
    if (!builder)
    {
        return -1;
    }

    builder->entropy_cb = entropy_cb;
    builder->entropy_ctx = entropy_ctx;
    return 0;
}

int
OTA_server_builder_enable_tls(OTA_server_builder_t* builder)
{
    if (!builder)
    {
        return -1;
    }

    builder->tls_enabled = true;
    return 0;
}

int
OTA_server_builder_set_pki_data(OTA_server_builder_t* builder,
                                const unsigned char* cert_data,
                                size_t cert_len,
                                const unsigned char* key_data,
                                size_t key_len)
{
    if (!builder || !cert_data || cert_len == 0 || !key_data || key_len == 0)
    {
        return -1;
    }

    // Free existing PKI data if any
    if (builder->pki_cert_data)
    {
        free(builder->pki_cert_data);
        builder->pki_cert_data = NULL;
    }
    if (builder->pki_key_data)
    {
        free(builder->pki_key_data);
        builder->pki_key_data = NULL;
    }

    // Allocate and copy certificate data
    builder->pki_cert_data = malloc(cert_len);
    if (!builder->pki_cert_data)
    {
        return -1;
    }
    memcpy(builder->pki_cert_data, cert_data, cert_len);
    builder->pki_cert_len = cert_len;

    // Allocate and copy key data
    builder->pki_key_data = malloc(key_len);
    if (!builder->pki_key_data)
    {
        free(builder->pki_cert_data);
        builder->pki_cert_data = NULL;
        return -1;
    }
    memcpy(builder->pki_key_data, key_data, key_len);
    builder->pki_key_len = key_len;

    return 0;
}

int
OTA_server_builder_set_sha512_private_key(OTA_server_builder_t* builder,
                                          const unsigned char* key_data,
                                          size_t key_len)
{
    if (!builder || !key_data || key_len == 0)
    {
        return -1;
    }

    // Free existing key data if any
    if (builder->sha512_private_key_data)
    {
        free(builder->sha512_private_key_data);
        builder->sha512_private_key_data = NULL;
    }

    // Allocate and copy key data
    builder->sha512_private_key_data = malloc(key_len);
    if (!builder->sha512_private_key_data)
    {
        return -1;
    }

    memcpy(builder->sha512_private_key_data, key_data, key_len);
    builder->sha512_private_key_len = key_len;
    return 0;
}

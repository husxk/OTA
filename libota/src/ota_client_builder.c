#include "libota/ota_client_builder.h"
#include "internal/ota_client_internal.h"
#include "libota/ota_common.h"
#include "libota/tls_context.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Internal builder structure
struct ota_client_builder
{
    // Common callbacks (shared with server)
    OTA_common_callbacks_t common_callbacks;

    // Client-specific callbacks
    OTA_client_callbacks_t client_callbacks;

    // TLS configuration
    bool tls_enabled;
    tls_entropy_cb_t entropy_cb;
    void* entropy_ctx;

    // SHA-512 public key for signature verification
    unsigned char* sha512_public_key_data;
    size_t sha512_public_key_len;
};

OTA_client_builder_t* OTA_client_builder_create(void)
{
    OTA_client_builder_t* builder = malloc(sizeof(OTA_client_builder_t));
    if (!builder)
    {
        return NULL;
    }

    memset(builder, 0, sizeof(OTA_client_builder_t));
    builder->tls_enabled = false;
    return builder;
}

void OTA_client_builder_destroy(OTA_client_builder_t* builder)
{
    if (builder)
    {
        // Free SHA-512 public key data if allocated
        if (builder->sha512_public_key_data)
        {
            free(builder->sha512_public_key_data);
        }
        free(builder);
    }
}

// Common callback setters
void
OTA_client_builder_set_transfer_send_cb(OTA_client_builder_t* builder,
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
OTA_client_builder_set_transfer_receive_cb(OTA_client_builder_t* builder,
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
OTA_client_builder_set_transfer_error_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   const char* error_msg))
{
    if (builder)
    {
        builder->common_callbacks.transfer_error_cb = cb;
    }
}

void
OTA_client_builder_set_transfer_done_cb(OTA_client_builder_t* builder,
                                              void (*cb)(void* ctx,
                                                         uint32_t total_bytes))
{
    if (builder)
    {
        builder->common_callbacks.transfer_done_cb = cb;
    }
}

void
OTA_client_builder_set_debug_log_cb(OTA_client_builder_t* builder,
                                    void (*cb)(void* ctx,
                                               const char* format,
                                               va_list args))
{
    if (builder)
    {
        builder->common_callbacks.debug_log_cb = cb;
    }
}

// Client-specific callback setters
void
OTA_client_builder_set_firmware_reboot_cb(OTA_client_builder_t* builder,
                                          void (*cb)(void))
{
    if (builder)
    {
        builder->client_callbacks.firmware_reboot_cb = cb;
    }
}

void
OTA_client_builder_set_firmware_read_cb(OTA_client_builder_t* builder,
                                       void (*cb)(void* ctx,
                                                 uint32_t current_addr,
                                                 const uint8_t** data,
                                                 size_t* size))
{
    if (builder)
    {
        builder->client_callbacks.firmware_read_cb = cb;
    }
}

void
OTA_client_builder_set_firmware_prepare_cb(OTA_client_builder_t* builder,
                                          void (*cb)(void* ctx))
{
    if (builder)
    {
        builder->client_callbacks.firmware_prepare_cb = cb;
    }
}

void
OTA_client_builder_set_firmware_write_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx,
                                                   uint32_t flash_addr,
                                                   const uint8_t* data,
                                                   size_t size))
{
    if (builder)
    {
        builder->client_callbacks.firmware_write_cb = cb;
    }
}

void
OTA_client_builder_set_transfer_store_cb(OTA_client_builder_t* builder,
                                        bool (*cb)(void* ctx,
                                                   const uint8_t* data,
                                                   size_t size))
{
    if (builder)
    {
        builder->client_callbacks.transfer_store_cb = cb;
    }
}

void
OTA_client_builder_set_transfer_reset_cb(OTA_client_builder_t* builder,
                                        void (*cb)(void* ctx))
{
    if (builder)
    {
        builder->client_callbacks.transfer_reset_cb = cb;
    }
}

// Configuration setters
int
OTA_client_builder_set_entropy_cb(OTA_client_builder_t* builder,
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
OTA_client_builder_enable_tls(OTA_client_builder_t* builder)
{
    if (!builder)
    {
        return -1;
    }

    builder->tls_enabled = true;
    return 0;
}

int
OTA_client_builder_set_sha512_public_key(OTA_client_builder_t* builder,
                                         const unsigned char* key_data,
                                         size_t key_len)
{
    if (!builder || !key_data || key_len == 0)
    {
        return -1;
    }

    // Free existing key data if any
    if (builder->sha512_public_key_data)
    {
        free(builder->sha512_public_key_data);
        builder->sha512_public_key_data = NULL;
    }

    // Allocate and copy key data
    builder->sha512_public_key_data = malloc(key_len);
    if (!builder->sha512_public_key_data)
    {
        return -1;
    }

    memcpy(builder->sha512_public_key_data, key_data, key_len);
    builder->sha512_public_key_len = key_len;
    return 0;
}

OTA_client_ctx*
OTA_client_builder_build(OTA_client_builder_t* builder, int* error_code)
{
    // Set default error code
    if (error_code)
    {
        *error_code = OTA_CLIENT_BUILDER_SUCCESS;
    }

    // Validate builder is not NULL
    if (!builder)
    {
        if (error_code)
        {
            *error_code = OTA_CLIENT_BUILDER_ERROR_NULL;
        }
        return NULL;
    }

    // Validate required callbacks
    if (!ota_common_callbacks_validate(&builder->common_callbacks) ||
        !builder->client_callbacks.firmware_reboot_cb              ||
        !builder->client_callbacks.firmware_read_cb                ||
        !builder->client_callbacks.firmware_prepare_cb             ||
        !builder->client_callbacks.firmware_write_cb               ||
        !builder->client_callbacks.transfer_store_cb               ||
        !builder->client_callbacks.transfer_reset_cb)
    {
        if (error_code)
        {
            *error_code = OTA_CLIENT_BUILDER_ERROR_MISSING_CB;
        }
        return NULL;
    }

    // Allocate context
    OTA_client_ctx* ctx = malloc(sizeof(OTA_client_ctx));
    if (!ctx)
    {
        if (error_code)
        {
            *error_code = OTA_CLIENT_BUILDER_ERROR_ALLOC;
        }
        return NULL;
    }

    // Zero-initialize context
    memset(ctx, 0, sizeof(OTA_client_ctx));

    // Copy common callbacks from builder to context
    ota_common_callbacks_copy(&ctx->common.callbacks,
                              &builder->common_callbacks);

    // Copy client-specific callbacks from builder to context
    ctx->firmware_reboot_cb  = builder->client_callbacks.firmware_reboot_cb;
    ctx->firmware_read_cb    = builder->client_callbacks.firmware_read_cb;
    ctx->firmware_prepare_cb = builder->client_callbacks.firmware_prepare_cb;
    ctx->firmware_write_cb   = builder->client_callbacks.firmware_write_cb;
    ctx->transfer_store_cb   = builder->client_callbacks.transfer_store_cb;
    ctx->transfer_reset_cb   = builder->client_callbacks.transfer_reset_cb;

    // Set entropy callback if provided (must be done before TLS init)
    if (builder->entropy_cb)
    {
        if (OTA_set_entropy_cb(builder->entropy_cb, builder->entropy_ctx) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_CLIENT_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Set SHA-512 public key if provided
    if (builder->sha512_public_key_data)
    {
        if (OTA_set_sha512_public_key(&ctx->common,
                                      builder->sha512_public_key_data,
                                      builder->sha512_public_key_len) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_CLIENT_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Enable TLS if requested
    if (builder->tls_enabled)
    {
        if (OTA_enable_tls(&ctx->common) != 0)
        {
            if (error_code)
            {
                *error_code = OTA_CLIENT_BUILDER_ERROR_ALLOC;
            }
            free(ctx);
            return NULL;
        }
    }

    // Initialize client context (includes TLS init if enabled)
    if (OTA_client_init(ctx) != 0)
    {
        if (error_code)
        {
            *error_code = OTA_CLIENT_BUILDER_ERROR_ALLOC;
        }
        free(ctx);
        return NULL;
    }

    // Context is fully initialized and ready to use
    return ctx;
}

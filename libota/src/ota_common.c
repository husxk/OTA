#include "ota_common.h"
#include "tls_context.h"
#include "protocol.h"
#include "packet.h"
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

// Static flag to track PSA crypto initialization state
static bool psa_crypto_initialized = false;

bool ota_common_callbacks_validate(const OTA_common_callbacks_t* callbacks)
{
    if (!callbacks)
    {
        return false;
    }

    // Validate required callbacks
    if (!callbacks->transfer_send_cb    ||
        !callbacks->transfer_receive_cb ||
        !callbacks->transfer_error_cb   ||
        !callbacks->transfer_done_cb)
    {
        return false;
    }

    return true;
}

void ota_common_callbacks_copy(OTA_common_callbacks_t* dest,
                               const OTA_common_callbacks_t* src)
{
    if (!dest || !src)
    {
        return;
    }

    // Copy each callback pointer
    dest->transfer_send_cb     = src->transfer_send_cb;
    dest->transfer_receive_cb  = src->transfer_receive_cb;
    dest->transfer_error_cb    = src->transfer_error_cb;
    dest->transfer_done_cb     = src->transfer_done_cb;
    dest->debug_log_cb         = src->debug_log_cb;
}

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

void ota_common_transfer_error(OTA_common_ctx_t* ctx,
                                void* user_ctx,
                                const char* error_msg)
{
    if (!ctx ||
        !ctx->callbacks.transfer_error_cb)
    {
        return;
    }

    ctx->callbacks.transfer_error_cb(user_ctx, error_msg);
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

    // Use TLS if enabled, otherwise use plain callback
    if (ctx->tls_enabled && ctx->tls)
    {
        tls_context_send(ctx->tls, data, size);
    }
    else if (ctx->callbacks.transfer_send_cb)
    {
        ctx->callbacks.transfer_send_cb(user_ctx, data, size);
    }
}

// TODO: We should collect data and create packet from it.
// Data could come fragmented or sth?
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

    // Use TLS if enabled, otherwise use plain callback
    if (ctx->tls_enabled && ctx->tls)
    {
        // Set user context if provided (needed for TLS callbacks)
        if (user_ctx)
        {
            ota_tls_set_user_context(ctx, user_ctx);
        }

        // Handshake checking is done inside tls_context_receive
        int ret = tls_context_receive(ctx->tls, buffer, max_size);

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

// Ensure PSA crypto is initialized
// Returns: 0 on success, negative value on error
// This function is safe to call multiple times
int ota_common_ensure_psa_crypto_init(void)
{
    if (psa_crypto_initialized)
    {
        return 0; // Already initialized
    }

    psa_status_t psa_ret = psa_crypto_init();
    if (psa_ret != PSA_SUCCESS)
    {
        return -(int)psa_ret;
    }

    psa_crypto_initialized = true;
    return 0;
}

int OTA_set_pki_data(OTA_common_ctx_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len)
{
    if (!ctx)
        return -1;

    // Allocate TLS context if not already allocated
    if (!ctx->tls)
    {
        ctx->tls = tls_context_alloc();
        if (!ctx->tls)
            return -1;
    }

    return tls_set_pki_data(ctx->tls, cert_data, cert_len, key_data, key_len);
}

bool ota_tls_is_pki_data_set(OTA_common_ctx_t* ctx)
{
    if (!ctx || !ctx->tls)
        return false;

    return tls_is_pki_data_set(ctx->tls);
}

void ota_tls_set_user_context(OTA_common_ctx_t* ctx, void* user_ctx)
{
    if (!ctx || !ctx->tls)
        return;

    tls_context_set_user_context(ctx->tls, user_ctx);
}

bool ota_tls_is_handshake_complete(OTA_common_ctx_t* ctx)
{
    if (!ctx || !ctx->tls)
        return false;

    return tls_context_handshake_complete(ctx->tls);
}

int ota_tls_close(OTA_common_ctx_t* ctx)
{
    if (!ctx || !ctx->tls)
        return -1;

    return tls_context_close(ctx->tls);
}

static int ota_tls_handshake(OTA_common_ctx_t* ctx, void* user_ctx)
{
    if (!ctx || !ctx->tls)
        return -1;

    // Set user context if provided
    if (user_ctx)
    {
        ota_tls_set_user_context(ctx, user_ctx);
    }

    return tls_context_handshake(ctx->tls);
}

static bool ota_common_tls_handshake_blocking(OTA_common_ctx_t* ctx,
                                              void* user_ctx)
{
    // Blocking mode: loop until handshake completes
    int ret;
    while ((ret = ota_tls_handshake(ctx, user_ctx)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // Handshake error
            char error_buf[256];
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));

                ota_common_debug_log(ctx, user_ctx,
                                     "Error: TLS handshake failed: %d (%s)\n",
                                     ret, error_buf);

                ota_common_transfer_error(ctx, user_ctx, "TLS handshake failed");

            return false;
        }
    }

    ota_common_debug_log(ctx, user_ctx,
                         "TLS handshake completed successfully\n");
    return true;
}

static bool ota_common_tls_handshake_nonblocking(OTA_common_ctx_t* ctx,
                                                 void* user_ctx)
{
    // Non-blocking mode: return immediately
    ota_common_debug_log(ctx, user_ctx,
                         "Handshake not complete, continuing...\n");

    int ret = ota_tls_handshake(ctx, user_ctx);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // Handshake needs more I/O
        ota_common_debug_log(ctx, user_ctx,
                             "Handshake needs more I/O (WANT_%s)\n",
                             (ret == MBEDTLS_ERR_SSL_WANT_READ) ?
                             "READ" : "WRITE");
        return true; // just needs more I/O
    }
    else if (ret != 0)
    {
        // Handshake error
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

            ota_common_debug_log(ctx, user_ctx,
                                 "Handshake error: %d (%s)\n",
                                 ret, error_buf);
            ota_common_transfer_error(ctx, user_ctx, "TLS handshake failed");
        return false;
    }

    // Handshake completed
    ota_common_debug_log(ctx, user_ctx,
                         "Handshake completed successfully!\n");
    return true;
}

bool ota_common_tls_handshake(OTA_common_ctx_t* ctx,
                              void* user_ctx,
                              bool blocking)
{
    if (!ctx || !ctx->tls)
        return false;

    // Check if handshake is already complete
    if (ota_tls_is_handshake_complete(ctx))
    {
        return true;
    }

    if (blocking)
    {
        return ota_common_tls_handshake_blocking(ctx, user_ctx);
    }
    else
    {
        return ota_common_tls_handshake_nonblocking(ctx, user_ctx);
    }
}

int ota_tls_set_endpoint(OTA_common_ctx_t* ctx, int endpoint)
{
    if (!ctx)
        return -1;

    // Allocate TLS context if not already allocated
    if (!ctx->tls)
    {
        ctx->tls = tls_context_alloc();
        if (!ctx->tls)
        {
            ota_common_debug_log(ctx, NULL,
                                 "Error: Failed to allocate TLS context\n");
            return -1;
        }
        tls_context_set_ota_context(ctx->tls, ctx);
    }

    return tls_context_set_endpoint(ctx->tls, endpoint);
}

int ota_common_tls_init(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Only initialize TLS if it's enabled
    if (!ctx->tls_enabled)
    {
        // TLS not enabled, skip initialization
        return 0;
    }

    if (!tls_is_entropy_callback_set())
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Entropy callback not set. "
                             "Call OTA_set_entropy_cb() first\n");
        return -1;
    }

    // Allocate TLS context if not already allocated
    if (!ctx->tls)
    {
        ctx->tls = tls_context_alloc();
        if (!ctx->tls)
        {
            ota_common_debug_log(ctx, NULL,
                                 "Error: Failed to allocate TLS context\n");
            return -1;
        }
    }

    tls_context_set_ota_context(ctx->tls, ctx);
    tls_context_set_user_context(ctx->tls, NULL); // Will be set when transfer starts

    ota_common_debug_log(ctx, NULL,
                         "Initializing TLS context...\n");

    int ret = tls_context_init(ctx->tls);
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

int OTA_enable_tls(OTA_common_ctx_t* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    ctx->tls_enabled = true;
    ota_common_debug_log(ctx, NULL,
                         "TLS transport enabled\n");

    return 0;
}

bool ota_tls_is_enabled(OTA_common_ctx_t* ctx)
{
    if (!ctx)
    {
        return false;
    }

    return ctx->tls_enabled;
}

int ota_common_tls_cleanup(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Close and free TLS context
    if (ctx->tls)
    {
        tls_context_close(ctx->tls);
        tls_context_free(ctx->tls);
        ctx->tls = NULL;
    }

    // Cleanup SHA-512 hash operation state, but preserve keys
    if (ctx->sha512.sha512_active)
    {
        psa_hash_abort(&ctx->sha512.sha512_operation);
    }

    memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));
    memset(ctx->sha512.sha512_hash, 0, sizeof(ctx->sha512.sha512_hash));
    memset(ctx->sha512.sha512_signature, 0, sizeof(ctx->sha512.sha512_signature));

    ctx->sha512.sha512_calculated = false;
    ctx->sha512.sha512_active = false;
    ctx->sha512.sha512_signature_length = 0;
    ctx->sha512.sha512_signed = false;

    // Note: We do NOT free sha512_private_key or sha512_public_key here
    // as they should persist across reconnections

    return 0;
}

int OTA_tls_restart(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Get endpoint type before cleanup (returns -1 if not set)
    int endpoint = -1;
    if (ctx->tls)
    {
        endpoint = tls_context_get_endpoint(ctx->tls);
    }

    // Close and free existing TLS context
    ota_common_tls_cleanup(ctx);

    // Re-initialize TLS if it was enabled and we have a valid endpoint
    if (ctx->tls_enabled && endpoint != -1)
    {
        // Allocate new TLS context and set endpoint
        ctx->tls = tls_context_alloc();
        if (!ctx->tls)
        {
            ota_common_debug_log(ctx, NULL,
                                 "Error: Failed to allocate TLS context\n");
            return -1;
        }

        tls_context_set_ota_context(ctx->tls, ctx);
        tls_context_set_endpoint(ctx->tls, endpoint);

        return ota_common_tls_init(ctx);
    }

    return 0;
}

int ota_common_cleanup(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Cleanup TLS context (preserves SHA-512 keys)
    ota_common_tls_cleanup(ctx);

    // Full SHA-512 cleanup including keys
    ota_common_sha512_cleanup(ctx);

    return 0;
}

int ota_common_sha512_init(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Cleanup any existing hash operation
    // Don't call full cleanup as it would free the private/public keys
    if (ctx->sha512.sha512_active)
    {
        psa_hash_abort(&ctx->sha512.sha512_operation);
    }

    // Reset all hash-related state
    // Note: We do NOT free sha512_private_key or sha512_public_key here
    // as they are set once and should persist across hash operations
    memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));
    memset(ctx->sha512.sha512_hash      , 0, sizeof(ctx->sha512.sha512_hash));
    memset(ctx->sha512.sha512_signature , 0, sizeof(ctx->sha512.sha512_signature));

    ctx->sha512.sha512_calculated       = false;
    ctx->sha512.sha512_active           = false;
    ctx->sha512.sha512_signature_length = 0;
    ctx->sha512.sha512_signed           = false;

    // Setup SHA-512 hash operation
    psa_status_t status =
        psa_hash_setup(&ctx->sha512.sha512_operation, PSA_ALG_SHA_512);
    if (status != PSA_SUCCESS)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to setup SHA-512: %d\n",
                             (int)status);

        // Cleanup on error
        psa_hash_abort(&ctx->sha512.sha512_operation);
        memset(&ctx->sha512.sha512_operation,
               0,
               sizeof(ctx->sha512.sha512_operation));

        ctx->sha512.sha512_active = false;

        return -1;
    }

    // Mark operation as active after successful setup
    ctx->sha512.sha512_active = true;

    ota_common_debug_log(ctx, NULL,
                         "SHA-512 hash calculation initialized\n");

    return 0;
}

int ota_common_sha512_update(OTA_common_ctx_t* ctx,
                             const uint8_t* data,
                             size_t size)
{
    if (!ctx  ||
        !data ||
        size == 0)
    {
         return -1;
    }

    // Check if operation is initialized
    if (!ctx->sha512.sha512_active)
    {
        int ret = ota_common_sha512_init(ctx);

        if (ret != 0)
            return ret;
    }

    // Update hash with data
    psa_status_t status = psa_hash_update(&ctx->sha512.sha512_operation, data, size);
    if (status != PSA_SUCCESS)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to update SHA-512: %d\n",
                             (int)status);

        psa_hash_abort(&ctx->sha512.sha512_operation);
        memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));
        ctx->sha512.sha512_active = false;

        return -1;
    }

    return 0;
}

int ota_common_sha512_finish(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Check if operation is initialized
    if (!ctx->sha512.sha512_active)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: SHA-512 operation not initialized\n");
        return -1;
    }

    // Finalize hash calculation
    size_t hash_length = 0;
    psa_status_t status = psa_hash_finish(&ctx->sha512.sha512_operation,
                                          ctx->sha512.sha512_hash,
                                          sizeof(ctx->sha512.sha512_hash),
                                          &hash_length);
    if (status != PSA_SUCCESS)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to finish SHA-512: %d\n",
                             (int)status);

        psa_hash_abort(&ctx->sha512.sha512_operation);
        memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));
        ctx->sha512.sha512_active = false;

        return -1;
    }

    if (hash_length != sizeof(ctx->sha512.sha512_hash))
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: SHA-512 hash length mismatch: "
                             "expected %zu, got %zu\n",
                             sizeof(ctx->sha512.sha512_hash), hash_length);

        psa_hash_abort(&ctx->sha512.sha512_operation);
        memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));
        ctx->sha512.sha512_active = false;

        return -1;
    }

    ctx->sha512.sha512_calculated = true;
    ctx->sha512.sha512_active = false; // Operation is finished, no longer active

    ota_common_debug_log(ctx, NULL,
                         "SHA-512 hash calculation completed\n");

    return 0;
}

int ota_common_sha512_sign(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    // Check if hash is calculated
    if (!ctx->sha512.sha512_calculated)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Cannot sign - SHA-512 hash not calculated\n");
        return -1;
    }

    // Check if already signed
    if (ctx->sha512.sha512_signed)
    {
        ota_common_debug_log(ctx, NULL,
                             "Warning: SHA-512 hash already signed\n");
        return 0;
    }

    // Check if private key is set
    if (!ctx->sha512.sha512_private_key)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Cannot sign - private key not set (pointer is NULL)\n");
        return -1;
    }

    ota_common_debug_log(ctx, NULL,
                         "Private key is set, proceeding with signing\n");

    // Use SHA-512 as the hash algorithm
    size_t signature_len = 0;
    int ret = mbedtls_pk_sign(ctx->sha512.sha512_private_key,
                              MBEDTLS_MD_SHA512,
                              ctx->sha512.sha512_hash,
                              sizeof(ctx->sha512.sha512_hash),
                              ctx->sha512.sha512_signature,
                              sizeof(ctx->sha512.sha512_signature),
                              &signature_len);

    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to sign SHA-512 hash: %d (%s)\n",
                             ret, error_buf);
        return -1;
    }

    // Validate signature length matches protocol requirement
    if (signature_len != OTA_SHA512_SIGNATURE_LENGTH)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Signature length mismatch: expected %d, got %zu\n",
                             OTA_SHA512_SIGNATURE_LENGTH, signature_len);
        return -1;
    }

    ctx->sha512.sha512_signature_length = signature_len;
    ctx->sha512.sha512_signed = true;

    ota_common_debug_log(ctx, NULL,
                         "SHA-512 hash signed successfully (%zu bytes)\n",
                         signature_len);

    return 0;
}

int ota_common_sha512_verify(OTA_common_ctx_t* ctx,
                             const uint8_t* signature,
                             size_t signature_len)
{
    if (!ctx)
        return -1;

    if (!signature)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Cannot verify - signature is NULL\n");
        return -1;
    }

    // Validate signature length matches protocol requirement
    if (signature_len != OTA_SHA512_SIGNATURE_LENGTH)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Signature length mismatch: expected %d, got %zu\n",
                             OTA_SHA512_SIGNATURE_LENGTH, signature_len);
        return -1;
    }

    // Check if hash is calculated
    if (!ctx->sha512.sha512_calculated)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Cannot verify - SHA-512 hash not calculated\n");
        return -1;
    }

    // Check if public key is set
    if (!ctx->sha512.sha512_public_key)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Cannot verify - "
                             "public key not set (pointer is NULL)\n");
        return -1;
    }

    ota_common_debug_log(ctx, NULL,
                         "Public key is set (pointer: %p), "
                         "proceeding with verification\n",
                         (void*)ctx->sha512.sha512_public_key);

    // Verify signature using public key
    ota_common_debug_log(ctx, NULL,
                         "Verifying signature against calculated hash...\n");

    int ret = mbedtls_pk_verify(ctx->sha512.sha512_public_key,
                                MBEDTLS_MD_SHA512,
                                ctx->sha512.sha512_hash,
                                sizeof(ctx->sha512.sha512_hash),
                                signature,
                                signature_len);

    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        ota_common_debug_log(ctx, NULL,
                             "Error: Signature verification failed: %d (%s)\n",
                             ret, error_buf);
        ota_common_debug_log(ctx, NULL,
                             "Hash does not match - signature verification failed\n");
        return -1;
    }

    ota_common_debug_log(ctx, NULL,
                         "Hash matches - SHA-512 signature verification successful\n");

    return 0;
}

void ota_common_sha512_cleanup(OTA_common_ctx_t* ctx)
{
    if (!ctx)
        return;

    // Abort any active hash operation
    if (ctx->sha512.sha512_active)
    {
        psa_hash_abort(&ctx->sha512.sha512_operation);
    }

    // Reset operation to initial state (zero-initialize)
    memset(&ctx->sha512.sha512_operation, 0, sizeof(ctx->sha512.sha512_operation));

    // Reset hash result and flags
    memset(ctx->sha512.sha512_hash, 0, sizeof(ctx->sha512.sha512_hash));
    ctx->sha512.sha512_calculated = false;
    ctx->sha512.sha512_active = false;

    // Reset signature
    memset(ctx->sha512.sha512_signature, 0, sizeof(ctx->sha512.sha512_signature));
    ctx->sha512.sha512_signature_length = 0;
    ctx->sha512.sha512_signed = false;

    // Free private key if allocated
    if (ctx->sha512.sha512_private_key)
    {
        mbedtls_pk_free(ctx->sha512.sha512_private_key);
        free(ctx->sha512.sha512_private_key);
        ctx->sha512.sha512_private_key = NULL;
    }

    // Free public key if allocated
    if (ctx->sha512.sha512_public_key)
    {
        mbedtls_pk_free(ctx->sha512.sha512_public_key);
        free(ctx->sha512.sha512_public_key);
        ctx->sha512.sha512_public_key = NULL;
    }
}

// helper function to set a key (private or public)
// is_private: true for private key, false for public key
// Returns: 0 on success, negative value on error
static int ota_common_set_pk_key(OTA_common_ctx_t* ctx,
                                  mbedtls_pk_context** key_ptr,
                                  const unsigned char* key_data,
                                  size_t key_len,
                                  bool is_private,
                                  const char* key_type_name,
                                  const char* operation_name)
{
    if (!ctx      ||
        !key_ptr  ||
        !key_data ||
         key_len == 0)
    {
        return -1;
    }

    // Ensure PSA crypto is initialized (required for key parsing)
    int init_ret = ota_common_ensure_psa_crypto_init();
    if (init_ret != 0)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: psa_crypto_init() failed: %d\n",
                             -init_ret);
        return -1;
    }

    // Free existing key if present
    if (*key_ptr)
    {
        mbedtls_pk_free(*key_ptr);
        free(*key_ptr);
        *key_ptr = NULL;
    }

    // Allocate new PK context
    *key_ptr = malloc(sizeof(mbedtls_pk_context));
    if (!*key_ptr)
    {
        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to allocate PK context"
                             " for SHA-512 %s\n",
                             operation_name);
        return -1;
    }

    // Initialize PK context
    mbedtls_pk_init(*key_ptr);

    // Parse key (supports PEM and DER formats)
    ota_common_debug_log(ctx, NULL,
                         "Parsing %s key for SHA-512 %s (length: %zu bytes)\n",
                         key_type_name, operation_name, key_len);

    int ret;
    if (is_private)
    {
        ret = mbedtls_pk_parse_key(*key_ptr, key_data, key_len, NULL, 0);
    }
    else
    {
        ret = mbedtls_pk_parse_public_key(*key_ptr, key_data, key_len);
    }

    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx, NULL,
                             "Error: Failed to parse %s key for SHA-512 %s: "
                             "%d (%s)\n",
                             key_type_name, operation_name, ret, error_buf);

        mbedtls_pk_free(*key_ptr);
        free(*key_ptr);
        *key_ptr = NULL;

        return -1;
    }

    ota_common_debug_log(ctx, NULL,
                         "%s key set for SHA-512 %s (pointer: %p)\n",
                         key_type_name, operation_name, (void*)*key_ptr);

    return 0;
}

int OTA_set_sha512_private_key(OTA_common_ctx_t* ctx,
                               const unsigned char* key_data,
                               size_t key_len)
{
    return ota_common_set_pk_key(ctx,
                                 &ctx->sha512.sha512_private_key,
                                 key_data,
                                 key_len,
                                 true, // is_private = true
                                 "private",
                                 "signing");
}

int OTA_set_sha512_public_key(OTA_common_ctx_t* ctx,
                              const unsigned char* key_data,
                              size_t key_len)
{
    return ota_common_set_pk_key(ctx,
                                 &ctx->sha512.sha512_public_key,
                                 key_data,
                                 key_len,
                                 false, // is_private = false
                                 "public",
                                 "verification");
}

bool ota_send_data_packet(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const uint8_t* data,
                          size_t size)
{
    if (!ctx || !data || size == 0)
    {
        return false;
    }

    uint8_t send_buffer[OTA_DATA_PACKET_LENGTH];
    size_t bytes_written =
        OTA_packet_write_data(send_buffer,
                              sizeof(send_buffer),
                              data,
                              size);

    if (bytes_written == 0)
    {
        ota_common_transfer_error(ctx, user_ctx,
                                  "Failed to create DATA packet");
        return false;
    }

    OTA_send_data(ctx, user_ctx, send_buffer, bytes_written);
    ota_common_debug_log(ctx, user_ctx,
                         "OTA: DATA packet sent (%zu bytes)\n", size);
    return true;
}

void ota_send_ack_packet(OTA_common_ctx_t* ctx, void* user_ctx)
{
    if (!ctx)
    {
        return;
    }

    uint8_t ack_buffer[OTA_ACK_PACKET_LENGTH];
    size_t ack_size = OTA_packet_write_ack(ack_buffer, sizeof(ack_buffer));
    if (ack_size > 0)
    {
        OTA_send_data(ctx, user_ctx, ack_buffer, ack_size);
    }
}

void ota_send_nack_packet(OTA_common_ctx_t* ctx, void* user_ctx)
{
    if (!ctx)
    {
        return;
    }

    uint8_t nack_buffer[OTA_NACK_PACKET_LENGTH];
    size_t nack_size = OTA_packet_write_nack(nack_buffer, sizeof(nack_buffer));
    if (nack_size > 0)
    {
        OTA_send_data(ctx, user_ctx, nack_buffer, nack_size);
    }
}

bool ota_send_fin_packet(OTA_common_ctx_t* ctx, void* user_ctx)
{
    if (!ctx)
    {
        return false;
    }

    uint8_t fin_buffer[OTA_FIN_PACKET_LENGTH];

    // Check if signature is available and has correct length
    if (!ctx->sha512.sha512_signed)
    {
        ota_common_transfer_error(ctx, user_ctx,
                                  "Cannot send FIN packet: "
                                  "signature not calculated");
        return false;
    }

    if (ctx->sha512.sha512_signature_length != OTA_SHA512_SIGNATURE_LENGTH)
    {
        ota_common_transfer_error(ctx, user_ctx,
                                  "Cannot send FIN packet: "
                                  "invalid signature length");
        return false;
    }

    size_t fin_size = OTA_packet_write_fin(fin_buffer,
                                           sizeof(fin_buffer),
                                           ctx->sha512.sha512_signature,
                                           ctx->sha512.sha512_signature_length);

    if (fin_size == 0)
    {
        ota_common_transfer_error(ctx, user_ctx,
                                  "Failed to create FIN packet");
        return false;
    }

    OTA_send_data(ctx, user_ctx, fin_buffer, fin_size);
    ota_common_debug_log(ctx, user_ctx,
                         "OTA: FIN packet sent with signature\n");
    return true;
}

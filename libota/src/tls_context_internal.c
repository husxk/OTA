#include "internal/ota_common.h"
#include "internal/tls_context_internal.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <psa/crypto_driver_random.h>
#include <psa/crypto_values.h>
#include <psa/crypto_types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Static storage for user-provided entropy callback
static tls_entropy_cb_t entropy_callback     = NULL;
static void*            entropy_callback_ctx = NULL;

// TLS context structure
struct tls_context
{
    // mbedTLS TLS context
    mbedtls_ssl_context* tls_ctx;

    // mbedTLS TLS config
    mbedtls_ssl_config* tls_config;

    // Ciphersuites array (must persist for lifetime of config)
    int ciphersuites[2];

    // OTA context for callbacks
    OTA_common_ctx_t* ota_ctx;
    void* user_ctx;

    // PKI data
    const unsigned char* cert_data;
    size_t cert_len;

    const unsigned char* key_data;
    size_t key_len;

    // Parsed PKI structures
    mbedtls_x509_crt* cert;
    mbedtls_pk_context* key;

    // Endpoint type (MBEDTLS_SSL_IS_SERVER or MBEDTLS_SSL_IS_CLIENT)
    int endpoint;

    // Initialization flag
    bool initialized;
};

// Platform entropy function called by mbedTLS PSA Crypto
// Calls user's entropy callback if set via ota_tls_set_entropy_callback()
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                  size_t *estimate_bits,
                                  unsigned char *output,
                                  size_t output_size)
{
    (void)flags;

    if (!output ||
        output_size == 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!entropy_callback)
        return PSA_ERROR_NOT_SUPPORTED;

    int ret = entropy_callback(entropy_callback_ctx, output, output_size);
    if (ret != 0)
        return PSA_ERROR_HARDWARE_FAILURE;

    if (estimate_bits)
        *estimate_bits = output_size * 8;

    return PSA_SUCCESS;
}

int ota_tls_set_entropy_callback(tls_entropy_cb_t entropy_cb, void* entropy_ctx)
{
    if (!entropy_cb)
        return -1;

    entropy_callback     = entropy_cb;
    entropy_callback_ctx = entropy_ctx;

    return 0;
}

bool ota_tls_is_entropy_callback_set(void)
{
    return entropy_callback != NULL;
}

int ota_tls_context_set_pki_data(tls_context_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len)
{
    if (!ctx)
        return -1;

    ctx->cert_data = cert_data;
    ctx->cert_len  = cert_len;
    ctx->key_data  = key_data;
    ctx->key_len   = key_len;

    return 0;
}

bool ota_tls_context_is_pki_data_set(tls_context_t* ctx)
{
    if (!ctx)
        return false;

    return (ctx->cert_data != NULL && ctx->cert_len > 0 &&
            ctx->key_data  != NULL && ctx->key_len  > 0);
}

static int tls_bio_send(void* ctx, const unsigned char* buf, size_t len)
{
    tls_context_t* tls_ctx = (tls_context_t*)ctx;

    if (!tls_ctx          ||
        !tls_ctx->ota_ctx ||
        !tls_ctx->ota_ctx->callbacks.transfer_send_cb)
    {
        return -1;
    }

    tls_ctx->ota_ctx->callbacks.transfer_send_cb(tls_ctx->user_ctx, buf, len);

    return (int)len;
}

static int tls_bio_recv(void* ctx, unsigned char* buf, size_t len)
{
    tls_context_t* tls_ctx = (tls_context_t*)ctx;

    if (!tls_ctx          ||
        !tls_ctx->ota_ctx ||
        !tls_ctx->ota_ctx->callbacks.transfer_receive_cb)
    {
        return -1;
    }

    size_t received = tls_ctx->ota_ctx->callbacks.transfer_receive_cb(
        tls_ctx->user_ctx, buf, len);

    return (int)received;
}

// Setup PKI (certificate and private key)
// Returns: 0 on success, negative value on error
static int tls_setup_pki(tls_context_t* ctx, mbedtls_ssl_config* config)
{
    if (!ctx->cert_data ||
        !ctx->key_data)
    {
        ctx->cert = NULL;
        ctx->key  = NULL;

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Warning: PKI data not provided\n");
        return 0; // PKI is optional
    }

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "Setting up PKI: cert_len=%zu, key_len=%zu\n",
                         ctx->cert_len, ctx->key_len);

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "Setting up PKI\n");

    // Allocate cert and key structures
    mbedtls_x509_crt* cert  = malloc(sizeof(mbedtls_x509_crt));
    mbedtls_pk_context* key = malloc(sizeof(mbedtls_pk_context));
    if (!cert || !key)
    {
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to allocate memory for cert/key\n");

        if (cert)
          free(cert);

        if (key)
          free(key);

        return -1;
    }

    ctx->cert = cert;
    ctx->key  = key;

    mbedtls_x509_crt_init(cert);
    mbedtls_pk_init(key);

    // Parse certificate
    // mbedTLS expects PEM data to be null-terminated
    // Server should have added null terminator, so cert_len includes it
    int ret = mbedtls_x509_crt_parse(cert, ctx->cert_data, ctx->cert_len);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to parse certificate: %d (%s)\n",
                             ret, error_buf);

        mbedtls_pk_free(key);
        mbedtls_x509_crt_free(cert);

        free(key);
        free(cert);

        ctx->cert = NULL;
        ctx->key = NULL;

        return ret;
    }

    // Parse private key
    // mbedTLS expects PEM data to be null-terminated
    // Server should have added null terminator, so key_len includes it
    ret = mbedtls_pk_parse_key(key, ctx->key_data, ctx->key_len, NULL, 0);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to parse private key: %d (%s)\n",
                             ret, error_buf);

        mbedtls_pk_free(key);
        mbedtls_x509_crt_free(cert);

        free(key);
        free(cert);

        ctx->cert = NULL;
        ctx->key = NULL;

        return ret;
    }

    // Configure mbedTLS with certificate and key
    // Note: mbedtls_ssl_conf_own_cert() stores pointers, so cert/key must remain valid
    ret = mbedtls_ssl_conf_own_cert(config, cert, key);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to configure certificate: %d (%s)\n",
                             ret, error_buf);

        mbedtls_pk_free(key);
        mbedtls_x509_crt_free(cert);

        free(key);
        free(cert);

        ctx->cert = NULL;
        ctx->key = NULL;

        return ret;
    }

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "PKI configured successfully\n");

    return 0;
}

tls_context_t* ota_tls_context_alloc(void)
{
    tls_context_t* ctx = (tls_context_t*) calloc(1, sizeof(tls_context_t));

    if (!ctx)
        return NULL;

    return ctx;
}

int ota_tls_context_init(tls_context_t* ctx)
{
    int ret = 0;

    mbedtls_ssl_context* ssl   = NULL;
    mbedtls_ssl_config* config = NULL;

    if (!ctx)
        return -1;

    // Get endpoint type (must be set before calling init)
    int endpoint = ctx->endpoint;
    if (endpoint != MBEDTLS_SSL_IS_SERVER &&
        endpoint != MBEDTLS_SSL_IS_CLIENT)
    {
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Endpoint type not set. "
                             "Call ota_tls_context_set_endpoint() first\n");
        return -1;
    }

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "Initializing PSA crypto...\n");

    int init_ret = ota_common_ensure_psa_crypto_init();
    if (init_ret != 0)
    {
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: psa_crypto_init() failed: %d\n",
                             -init_ret);
        ret = init_ret;
        goto cleanup;
    }

    ssl = malloc(sizeof(mbedtls_ssl_context));
    if (!ssl)
    {
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to allocate SSL context\n");
        ret = -1;
        goto cleanup;
    }

    config = malloc(sizeof(mbedtls_ssl_config));
    if (!config)
    {
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: Failed to allocate SSL config\n");
        ret = -1;
        goto cleanup;
    }

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(config);

    ret = mbedtls_ssl_config_defaults(config,
                                      endpoint,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: ssl_config_defaults() failed: %d (%s)\n",
                             ret, error_buf);
        goto cleanup;
    }

    mbedtls_ssl_conf_min_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_3);

    ctx->ciphersuites[0] = MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256;
    ctx->ciphersuites[1] = 0;
    mbedtls_ssl_conf_ciphersuites(config, ctx->ciphersuites);

    mbedtls_ssl_conf_authmode(config, MBEDTLS_SSL_VERIFY_NONE);

    // Setup PKI data if provided
    // For server, PKI is required
    if (endpoint == MBEDTLS_SSL_IS_SERVER)
    {
        if (!ota_tls_context_is_pki_data_set(ctx))
        {
            ota_common_debug_log(ctx->ota_ctx, NULL,
                                 "Error: Server requires certificate and key\n");
            ret = -1;
            goto cleanup;
        }
    }

    ret = tls_setup_pki(ctx, config);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: tls_setup_pki() failed: %d (%s)\n",
                             ret, error_buf);
        goto cleanup;
    }

    ret = mbedtls_ssl_setup(ssl, config);
    if (ret != 0)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: ssl_setup() failed: %d (%s)\n",
                             ret, error_buf);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(ssl, ctx, tls_bio_send, tls_bio_recv, NULL);

    // Free any existing TLS context before assigning new one
    if (ctx->tls_ctx)
    {
        mbedtls_ssl_free(ctx->tls_ctx);
        free(ctx->tls_ctx);
        ctx->tls_ctx = NULL;
    }

    if (ctx->tls_config)
    {
        mbedtls_ssl_config_free(ctx->tls_config);
        free(ctx->tls_config);
        ctx->tls_config = NULL;
    }

    ctx->tls_ctx = ssl;
    ctx->tls_config = config;
    ctx->initialized = true;

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "TLS context initialized successfully\n");

    return 0;

cleanup:

    // Free PKI structures if allocated

    if (ctx->key)
    {
        mbedtls_pk_free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    if (ctx->cert)
    {
        mbedtls_x509_crt_free(ctx->cert);
        free(ctx->cert);
        ctx->cert = NULL;
    }

    if (config)
    {
        mbedtls_ssl_config_free(config);
        free(config);
    }

    if (ssl)
    {
        mbedtls_ssl_free(ssl);
        free(ssl);
    }

    return ret;
}

int ota_tls_context_handshake(tls_context_t* ctx)
{
    if (!ctx ||
        !ctx->initialized)
    {
        return -1;
    }

    if (ota_tls_context_handshake_complete(ctx))
      return 0;

    mbedtls_ssl_context* ssl = ctx->tls_ctx;
    if (!ssl)
        return -1;

    // Perform handshake
    int ret = mbedtls_ssl_handshake(ssl);

    if (ret == 0)
    {
        // Handshake completed
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "TLS handshake completed successfully\n");
        return 0;
    }
    else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // Handshake needs more I/O
        return ret;
    }
    else
    {
        // Handshake error
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));

        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error: TLS handshake failed: %d (%s)\n",
                             ret, error_buf);
        return ret;
    }
}

bool ota_tls_context_handshake_complete(tls_context_t* ctx)
{
    if (!ctx              ||
        !ctx->initialized ||
        !ctx->tls_ctx)
    {
        return false;
    }

    mbedtls_ssl_context* ssl = ctx->tls_ctx;
    return (mbedtls_ssl_is_handshake_over(ssl) != 0);
}

void ota_tls_context_set_user_context(tls_context_t* ctx, void* user_ctx)
{
    if (!ctx)
        return;

    ctx->user_ctx = user_ctx;
}

void ota_tls_context_set_ota_context(tls_context_t* ctx, OTA_common_ctx_t* ota_ctx)
{
    if (!ctx)
        return;

    ctx->ota_ctx = ota_ctx;
}

bool ota_tls_context_is_initialized(tls_context_t* ctx)
{
    if (!ctx)
        return false;

    return ctx->initialized;
}

int ota_tls_context_set_endpoint(tls_context_t* ctx, int endpoint)
{
    if (!ctx)
        return -1;

    if (endpoint != MBEDTLS_SSL_IS_SERVER &&
        endpoint != MBEDTLS_SSL_IS_CLIENT)
    {
        return -1;
    }

    ctx->endpoint = endpoint;
    return 0;
}

int ota_tls_context_get_endpoint(tls_context_t* ctx)
{
    if (!ctx)
        return -1;

    return ctx->endpoint;
}

static bool ota_tls_context_ensure_handshake(tls_context_t* ctx)
{
    if (!ctx || !ctx->initialized)
    {
        return false;
    }

    // Check if handshake is already complete
    if (ota_tls_context_handshake_complete(ctx))
    {
        return true;
    }

    // Handshake not complete, try to perform it (non-blocking)
    int handshake_ret = ota_tls_context_handshake(ctx);

    if (handshake_ret != 0 &&
        handshake_ret != MBEDTLS_ERR_SSL_WANT_READ &&
        handshake_ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // Handshake error
        return false;
    }

    // Return true if handshake is now complete, false if still in progress
    return ota_tls_context_handshake_complete(ctx);
}

int ota_tls_context_send(tls_context_t* ctx,
                     const uint8_t* data,
                     size_t size)
{
    if (!ctx              ||
        !ctx->initialized ||
        !data             ||
        size == 0)
    {
        return -1;
    }

    mbedtls_ssl_context* ssl = ctx->tls_ctx;
    if (!ssl)
        return -1;

    // Ensure handshake is complete before sending
    if (!ota_tls_context_ensure_handshake(ctx))
    {
        // Handshake not complete or error, cannot send data yet
        return 0;
    }

    size_t total_sent = 0;

    while (total_sent < size)
    {
        int ret = mbedtls_ssl_write(ssl, data + total_sent, size - total_sent);

        if (ret < 0)
        {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            return ret;
        }

        total_sent += (size_t)ret;
    }

    return (int)total_sent;
}

int ota_tls_context_receive(tls_context_t* ctx,
                        uint8_t* data,
                        size_t size)
{
    if (!ctx              ||
        !ctx->initialized ||
        !data             ||
        size == 0)
    {
        return -1;
    }

    mbedtls_ssl_context* ssl = ctx->tls_ctx;
    if (!ssl)
        return -1;

    // Ensure handshake is complete before reading
    if (!ota_tls_context_ensure_handshake(ctx))
    {
        // Handshake not complete or error, no data available yet
        return 0;
    }

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "Attempting to read up to %zu bytes\n",
                         size);

    int ret = mbedtls_ssl_read(ssl, data, size);

    if (ret < 0)
    {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ota_common_debug_log(ctx->ota_ctx, NULL,
                                 "Need more I/O (WANT_%s)\n",
                                 (ret == MBEDTLS_ERR_SSL_WANT_READ) ? "READ" : "WRITE");
            return 0;
        }

        // Error
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        ota_common_debug_log(ctx->ota_ctx, NULL,
                             "Error reading: %d (%s)\n",
                             ret, error_buf);
        return ret;
    }

    ota_common_debug_log(ctx->ota_ctx, NULL,
                         "Read %d bytes of decrypted data\n",
                         ret);

    return ret;
}

int ota_tls_context_close(tls_context_t* ctx)
{
    if (!ctx ||
        !ctx->initialized)
    {
        return -1;
    }

    mbedtls_ssl_context* ssl = ctx->tls_ctx;
    if (!ssl)
        return -1;

    int ret;
    while ((ret = mbedtls_ssl_close_notify(ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            return ret;
    }

    return 0;
}

int ota_tls_context_free(tls_context_t* ctx)
{
    if (!ctx)
        return -1;

    if (ctx->initialized)
    {
        // Close connection gracefully first
        ota_tls_context_close(ctx);

        if (ctx->tls_ctx)
        {
            mbedtls_ssl_free(ctx->tls_ctx);
            free(ctx->tls_ctx);
            ctx->tls_ctx = NULL;
        }

        if (ctx->tls_config)
        {
            mbedtls_ssl_config_free(ctx->tls_config);
            free(ctx->tls_config);
            ctx->tls_config = NULL;
        }

        // Free PKI structures if allocated
        if (ctx->key)
        {
            mbedtls_pk_free(ctx->key);
            free(ctx->key);
            ctx->key = NULL;
        }

        if (ctx->cert)
        {
            mbedtls_x509_crt_free(ctx->cert);
            free(ctx->cert);
            ctx->cert = NULL;
        }

        ctx->initialized = false;
    }

    // Free the context itself
    free(ctx);
    return 0;
}


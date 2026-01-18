#pragma once

#include "libota/tls_context.h"
#include "internal/ota_common.h"
#include <stdbool.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#ifdef __cplusplus
extern "C" {
#endif

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

// Allocate TLS context
// Returns: pointer to allocated context, or NULL on error
tls_context_t* ota_tls_context_alloc(void);

// Initialize TLS context
// Note: Call ota_tls_context_set_endpoint() before calling this function
// Returns: 0 on success, negative value on error
int ota_tls_context_init(tls_context_t* ctx);

// Perform TLS handshake
// Returns: 0 on success, MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE, negative on error
int ota_tls_context_handshake(tls_context_t* ctx);

// Check if TLS handshake is complete
// Returns: true if handshake is complete, false otherwise
bool ota_tls_context_handshake_complete(tls_context_t* ctx);

// Set user context for TLS callbacks
void ota_tls_context_set_user_context(tls_context_t* ctx, void* user_ctx);

// Set OTA context for TLS callbacks
void ota_tls_context_set_ota_context(tls_context_t* ctx, OTA_common_ctx_t* ota_ctx);

// Check if TLS context is initialized
// Returns: true if initialized, false otherwise
bool ota_tls_context_is_initialized(tls_context_t* ctx);

// Set endpoint type for TLS context
// endpoint: MBEDTLS_SSL_IS_SERVER or MBEDTLS_SSL_IS_CLIENT
// Returns: 0 on success, negative value on error
int ota_tls_context_set_endpoint(tls_context_t* ctx, int endpoint);

// Get endpoint type from TLS context
// Returns: MBEDTLS_SSL_IS_SERVER or MBEDTLS_SSL_IS_CLIENT, or -1 if not set
int ota_tls_context_get_endpoint(tls_context_t* ctx);

// Send data through TLS connection
// Returns: number of bytes sent on success, negative value on error
int ota_tls_context_send(tls_context_t* ctx,
                         const uint8_t* data,
                         size_t size);

// Receive data through TLS connection
// Returns: number of bytes received on success, negative value on error
int ota_tls_context_receive(tls_context_t* ctx,
                             uint8_t* data,
                             size_t size);

// Set entropy callback for platform entropy collection
// Returns: 0 on success, negative value on error
int ota_tls_set_entropy_callback(tls_entropy_cb_t entropy_cb, void* entropy_ctx);

// Check if entropy callback is set
// Returns: true if entropy callback is set, false otherwise
bool ota_tls_is_entropy_callback_set(void);

// Set PKI data (certificate and private key) for server mode
// Data is stored as shallow copy
// Returns: 0 on success, negative value on error
int ota_tls_context_set_pki_data(tls_context_t* ctx,
                                   const unsigned char* cert_data,
                                   size_t cert_len,
                                   const unsigned char* key_data,
                                   size_t key_len);

// Check if PKI data is set
// Returns: true if PKI data is set, false otherwise
bool ota_tls_context_is_pki_data_set(tls_context_t* ctx);

// Close TLS connection gracefully
// Returns: 0 on success, negative value on error
int ota_tls_context_close(tls_context_t* ctx);

// Free TLS context and cleanup resources
// Returns: 0 on success, negative value on error
int ota_tls_context_free(tls_context_t* ctx);

#ifdef __cplusplus
}
#endif

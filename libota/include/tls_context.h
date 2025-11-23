#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct ota_common_ctx;
typedef struct ota_common_ctx OTA_common_ctx_t;

// Entropy callback function type
// Returns: 0 on success, negative value on error
typedef int (*tls_entropy_cb_t)(void* ctx, unsigned char* output, size_t len);

// Basic TLS context structure
typedef struct
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

    // Initialization flag
    bool initialized;

} tls_context_t;

// Initialize TLS context
// endpoint: MBEDTLS_SSL_IS_SERVER for server mode,
//           MBEDTLS_SSL_IS_CLIENT for client mode
// Returns: 0 on success, negative value on error
int tls_context_init(tls_context_t* ctx, int endpoint);

// Perform TLS handshake
// Returns: 0 on success, MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE, negative on error
int tls_context_handshake(tls_context_t* ctx);

// Check if TLS handshake is complete
// Returns: true if handshake is complete, false otherwise
bool tls_context_handshake_complete(tls_context_t* ctx);

// Send data through TLS connection
// Returns: number of bytes sent on success, negative value on error
int tls_context_send(tls_context_t* ctx,
                     const uint8_t* data,
                     size_t size);

// Receive data through TLS connection
// Returns: number of bytes received on success, negative value on error
int tls_context_receive(tls_context_t* ctx,
                        uint8_t* data,
                        size_t size);

// Set entropy callback for platform entropy collection
// Returns: 0 on success, negative value on error
int tls_set_entropy_callback(tls_entropy_cb_t entropy_cb, void* entropy_ctx);

// Check if entropy callback is set
// Returns: true if entropy callback is set, false otherwise
bool tls_is_entropy_callback_set(void);

// Set PKI data (certificate and private key) for server mode
// Data is stored as shallow copy
// Returns: 0 on success, negative value on error
int tls_set_pki_data(tls_context_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len);

// Check if PKI data is set
// Returns: true if PKI data is set, false otherwise
bool tls_is_pki_data_set(tls_context_t* ctx);

// Close TLS connection gracefully
// Returns: 0 on success, negative value on error
int tls_context_close(tls_context_t* ctx);

// Free TLS context and cleanup resources
// Returns: 0 on success, negative value on error
int tls_context_free(tls_context_t* ctx);

#ifdef __cplusplus
}
#endif

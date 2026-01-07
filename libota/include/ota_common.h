#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include "tls_context.h"
#include "protocol.h"
#include <psa/crypto.h>
#include <mbedtls/pk.h>

#ifdef __cplusplus
extern "C" {
#endif

// SHA-512 hash context for image verification
typedef struct
{
    // PSA hash operation for streaming calculation
    psa_hash_operation_t sha512_operation;

    // Flag indicating if SHA-512 operation is active (initialized)
    bool sha512_active;

    // SHA-512 hash result (64 bytes for SHA-512)
    // Set to all zeros when hash is not calculated
    uint8_t sha512_hash[64];

    // Flag indicating if SHA-512 hash has been calculated
    bool sha512_calculated;

    // Private key for signing
    mbedtls_pk_context* sha512_private_key;

    // Public key for signature verification
    mbedtls_pk_context* sha512_public_key;

    // Signature result (SHA-512 signature length)
    uint8_t sha512_signature[OTA_SHA512_SIGNATURE_LENGTH];

    // Actual signature length
    size_t sha512_signature_length;

    // Flag indicating if signature has been calculated
    bool sha512_signed;
} ota_sha512_ctx_t;

// Common transfer callbacks shared between client and server
typedef struct
{
    // Network transfer callbacks
    // Sends data over the network connection
    void (*transfer_send_cb) (void* ctx,
                              const uint8_t* data,
                              size_t size);

    // Receives data from the network connection
    // Returns: number of bytes actually received
    size_t (*transfer_receive_cb) (void* ctx,
                                   uint8_t* buffer,
                                   size_t max_size);

    // Handles transfer errors
    void (*transfer_error_cb) (void* ctx,
                               const char* error_msg);

    // Called when transfer is successfully completed
    void (*transfer_done_cb) (void* ctx,
                              uint32_t total_bytes);

    // Debug/Logging callback
    void (*debug_log_cb) (void* ctx,
                          const char* format,
                          va_list args);

} OTA_common_callbacks_t;

// Common OTA context structure (full definition)
struct ota_common_ctx
{
    // Common callbacks
    OTA_common_callbacks_t callbacks;

    // TLS context
    tls_context_t* tls;

    // TLS enabled flag
    bool tls_enabled;

    // SHA-512 hash context for image verification
    ota_sha512_ctx_t sha512;
};

// Common debug logging function
void ota_common_debug_log(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const char* format,
                          ...);

// Common transfer error logging function
void ota_common_transfer_error(OTA_common_ctx_t* ctx,
                               void* user_ctx,
                               const char* error_msg);

// Common send wrapper function
// Uses TLS if available, otherwise calls transfer_send_cb
void OTA_send_data(OTA_common_ctx_t* ctx,
                   void* user_ctx,
                   const uint8_t* data,
                   size_t size);

// Common receive wrapper function
// Uses TLS if available, otherwise calls transfer_receive_cb
// Returns: number of bytes received on success, 0 on error or no data
size_t OTA_recv_data(OTA_common_ctx_t* ctx,
                     void* user_ctx,
                     uint8_t* buffer,
                     size_t max_size);

// Set entropy callback for TLS
// Returns: 0 on success, negative value on error
int OTA_set_entropy_cb(tls_entropy_cb_t entropy_cb, void* entropy_ctx);

// Ensure PSA crypto is initialized
// Returns: 0 on success, negative value on error
// This function is idempotent - safe to call multiple times
int ota_common_ensure_psa_crypto_init(void);

// Set TLS endpoint type
// endpoint: MBEDTLS_SSL_IS_SERVER for server mode, MBEDTLS_SSL_IS_CLIENT for client mode
// Returns: 0 on success, negative value on error
int ota_tls_set_endpoint(OTA_common_ctx_t* ctx, int endpoint);

// Initialize TLS context
// Note: Endpoint type must be set before calling this (via ota_tls_set_endpoint)
// Returns: 0 on success, negative value on error
int ota_common_tls_init(OTA_common_ctx_t* ctx);

// Enable TLS transport
// Returns: 0 on success, negative value on error
int OTA_enable_tls(OTA_common_ctx_t* ctx);

// Check if TLS is enabled
// Returns: true if TLS is enabled, false otherwise
bool ota_tls_is_enabled(OTA_common_ctx_t* ctx);

// Cleanup TLS context
// Returns: 0 on success, negative value on error
int ota_common_tls_cleanup(OTA_common_ctx_t* ctx);

// Restart TLS context (for reconnection scenarios)
// Cleans up existing TLS context and re-initializes if TLS is enabled
// Returns: 0 on success, negative value on error
int OTA_tls_restart(OTA_common_ctx_t* ctx);

// Full cleanup of common context (TLS + SHA-512 keys)
// Use this for final destruction, not for reconnection scenarios
// Returns: 0 on success, negative value on error
int ota_common_cleanup(OTA_common_ctx_t* ctx);

// Set PKI data (certificate and private key) for TLS server mode
// Must be called before OTA_server_init
// Data is stored as shallow copy.
// Returns: 0 on success, negative value on error
int OTA_set_pki_data(OTA_common_ctx_t* ctx,
                     const unsigned char* cert_data,
                     size_t cert_len,
                     const unsigned char* key_data,
                     size_t key_len);

// Check if PKI data is set
// Returns: true if PKI data is set, false otherwise
bool ota_tls_is_pki_data_set(OTA_common_ctx_t* ctx);

// Set user context for TLS callbacks
// user_ctx: User context to set
void ota_tls_set_user_context(OTA_common_ctx_t* ctx, void* user_ctx);

// Perform TLS handshake with error handling and logging
// user_ctx: User context for TLS callbacks
// blocking: If true, loops until handshake completes (blocking mode)
//           If false, returns immediately on WANT_READ/WANT_WRITE (non-blocking mode)
// Returns: true on success (handshake complete),
//          false on error
//          In non-blocking mode, returns true if handshake needs more I/O
bool ota_common_tls_handshake(OTA_common_ctx_t* ctx, void* user_ctx, bool blocking);

// Check if TLS handshake is complete
// Returns: true if handshake is complete, false otherwise
bool ota_tls_is_handshake_complete(OTA_common_ctx_t* ctx);

// Close TLS connection gracefully
// Returns: 0 on success, negative value on error
int ota_tls_close(OTA_common_ctx_t* ctx);

// Internal SHA-512 functions
// Initialize SHA-512 hash calculation
// Returns: 0 on success, negative value on error
int ota_common_sha512_init(OTA_common_ctx_t* ctx);

// Update SHA-512 hash with data chunk
// Returns: 0 on success, negative value on error
int ota_common_sha512_update(OTA_common_ctx_t* ctx,
                             const uint8_t* data,
                             size_t size);

// Finalize SHA-512 hash calculation
// Returns: 0 on success, negative value on error
int ota_common_sha512_finish(OTA_common_ctx_t* ctx);

// Cleanup SHA-512 context
void ota_common_sha512_cleanup(OTA_common_ctx_t* ctx);

// Sign the calculated SHA-512 hash with private key
// Returns: 0 on success, negative value on error
int ota_common_sha512_sign(OTA_common_ctx_t* ctx);

// Verify signature against calculated SHA-512 hash using public key
// signature: Pointer to signature data
// signature_len: Length of signature data (must be OTA_SHA512_SIGNATURE_LENGTH)
// Returns: 0 on success (signature is valid), negative value on error
int ota_common_sha512_verify(OTA_common_ctx_t* ctx,
                             const uint8_t* signature,
                             size_t signature_len);

// Set private key for SHA-512 signing
// key_data: Pointer to key data in PEM or DER format
// key_len: Length of key data
// Returns: 0 on success, negative value on error
int OTA_set_sha512_private_key(OTA_common_ctx_t* ctx,
                               const unsigned char* key_data,
                               size_t key_len);

// Set public key for SHA-512 signature verification
// key_data: Pointer to key data in PEM or DER format
// key_len: Length of key data
// Returns: 0 on success, negative value on error
int OTA_set_sha512_public_key(OTA_common_ctx_t* ctx,
                              const unsigned char* key_data,
                              size_t key_len);

// Send DATA packet
// data: Pointer to data to send
// size: Size of data to send
// user_ctx: User context for callbacks
// Returns: true on success, false on error
bool ota_send_data_packet(OTA_common_ctx_t* ctx,
                          void* user_ctx,
                          const uint8_t* data,
                          size_t size);

// Send ACK packet
// user_ctx: User context for callbacks
void ota_send_ack_packet(OTA_common_ctx_t* ctx, void* user_ctx);

// Send NACK packet
// user_ctx: User context for callbacks
void ota_send_nack_packet(OTA_common_ctx_t* ctx, void* user_ctx);

// Send FIN packet with signature
// user_ctx: User context for callbacks
// Returns: true on success, false on error
bool ota_send_fin_packet(OTA_common_ctx_t* ctx, void* user_ctx);

#ifdef __cplusplus
}
#endif

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Entropy callback function type
// Returns: 0 on success, negative value on error
typedef int (*tls_entropy_cb_t)(void* ctx, unsigned char* output, size_t len);

// TLS context structure
typedef struct tls_context tls_context_t;

#ifdef __cplusplus
}
#endif

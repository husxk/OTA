#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Error: TARGET parameter is required"
    echo "Usage: $0 <TARGET> <OUTPUT_DIR>"
    echo "Example: $0 baremetal"
    echo "Example: $0 baremetal /path/to/output"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBOTA_DIR="$(dirname "$SCRIPT_DIR")"
MBEDTLS_DIR="${LIBOTA_DIR}/libs/mbedtls"

OUTPUT_CONFIG="${OUTPUT_DIR}/mbedtls_config.h"
OUTPUT_CRYPTO_CONFIG="${OUTPUT_DIR}/mbedtls_crypto_config.h"

SOURCE_CRYPTO_CONFIG="${MBEDTLS_DIR}/tf-psa-crypto/include/psa/crypto_config.h"
CONFIG_SCRIPT="${MBEDTLS_DIR}/scripts/config.py"

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

cp "${SOURCE_CRYPTO_CONFIG}" "${OUTPUT_CRYPTO_CONFIG}"

"${CONFIG_SCRIPT}" \
    -w "${OUTPUT_CONFIG}" \
    -c "${OUTPUT_CRYPTO_CONFIG}" \
    "${TARGET}"

# TODO: Fix this?
# Disable builtin keys feature (we provide keys manually via mbedtls_ssl_conf_own_cert)
sed -i 's/^#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS$/\/\/#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS/' "${OUTPUT_CRYPTO_CONFIG}"

echo "mbedTLS configuration files generated:"
echo "  ${OUTPUT_CONFIG}"
echo "  ${OUTPUT_CRYPTO_CONFIG}"

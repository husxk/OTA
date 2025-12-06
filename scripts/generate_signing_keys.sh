#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${REPO_ROOT}/build"

PRIVATE_KEY_FILE="${BUILD_DIR}/signing.key"
PUBLIC_KEY_FILE="${BUILD_DIR}/signing.pub"

# Create build directory if it doesn't exist
mkdir -p "${BUILD_DIR}"

echo "Generating signing key pair..."

# Generate private key (RSA 2048 bits) in PEM format
# Use -traditional to ensure PEM format (not OpenSSH format)
openssl genrsa -traditional -out "${PRIVATE_KEY_FILE}" 2048

# Ensure private key file ends with newline (for proper PEM parsing)
if [ "$(tail -c 1 "${PRIVATE_KEY_FILE}")" != "" ]; then
    echo "" >> "${PRIVATE_KEY_FILE}"
fi

# Generate public key from private key
openssl rsa -in "${PRIVATE_KEY_FILE}" -pubout -out "${PUBLIC_KEY_FILE}"

# Ensure public key file ends with newline
if [ "$(tail -c 1 "${PUBLIC_KEY_FILE}")" != "" ]; then
    echo "" >> "${PUBLIC_KEY_FILE}"
fi

echo "Signing keys generated successfully:"
echo "  Private Key: ${PRIVATE_KEY_FILE}"
echo "  Public Key:  ${PUBLIC_KEY_FILE}"

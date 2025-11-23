#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${SERVER_DIR}/build"

CERT_FILE="${BUILD_DIR}/server.crt"
KEY_FILE="${BUILD_DIR}/server.key"

# Create build directory if it doesn't exist
mkdir -p "${BUILD_DIR}"

echo "Generating private key and self-signed certificate..."

# Generate private key (RSA 2048 bits)
openssl genrsa -out "${KEY_FILE}" 2048

# Generate self-signed certificate (valid for 365 days)
openssl req -new -x509 -key "${KEY_FILE}" -out "${CERT_FILE}" -days 365 \
    -subj "/C=US/ST=State/L=City/O=OTA/CN=localhost"

echo "Certificate generated successfully:"
echo "  Certificate: ${CERT_FILE}"
echo "  Private Key: ${KEY_FILE}"

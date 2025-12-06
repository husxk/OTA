#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
ZERO='\033[0;0m'

MAIN_NAME="ota_server"
BUILD_DIR="build"
DEVICE_BIN="${BUILD_DIR}/device.bin"
DEVICE_BIN_BACKUP="${BUILD_DIR}/.device.bin"
CERT_FILE="${BUILD_DIR}/server.crt"
KEY_FILE="${BUILD_DIR}/server.key"

# Path to signing key in root build directory
# Script is in server/scripts/, so go up two levels to get to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$SERVER_DIR")"
SIGNING_KEY_FILE="${REPO_ROOT}/build/signing.key"

# Check if running in debug mode
DEBUG_MODE=false
if [ "$1" = "--debug" ] || [ "$1" = "-d" ]; then
    DEBUG_MODE=true
fi

# Rotate device.bin files if .device.bin exists
if [ -f "${DEVICE_BIN_BACKUP}" ]; then
    echo -e "${GREEN}Rotating device.bin files...${ZERO}"
    cd "${BUILD_DIR}"
    if [ -f device.bin ]; then
        mv device.bin device.bin.tmp
        mv .device.bin device.bin
        mv device.bin.tmp .device.bin
    else
        mv .device.bin device.bin
    fi
    cd ..
fi

# Check if signing key exists
if [ ! -f "${SIGNING_KEY_FILE}" ]; then
    echo -e "${RED}Error: Signing key not found at ${SIGNING_KEY_FILE}${ZERO}"
    echo -e "${RED}Please run 'make' in the root directory to generate signing keys${ZERO}"
    exit 1
fi

# Run the server
echo -e "${GREEN}Running ${PURPLE}${MAIN_NAME}${GREEN} with device.bin...${ZERO}"
cd "${BUILD_DIR}"

if [ "$DEBUG_MODE" = true ]; then
    gdb --args ./${MAIN_NAME} device.bin server.crt server.key "${SIGNING_KEY_FILE}"
else
    ./${MAIN_NAME} device.bin server.crt server.key "${SIGNING_KEY_FILE}"
fi

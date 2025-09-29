#!/bin/bash

set -e

echo "Building OTA project..."

# Build libota for both native and pico
echo "Building libota for native and pico..."
cd libota

# Build native version
echo "  Building native version..."
make clean
CMAKE_INSTALL_PREFIX="$(pwd)/../build/x86" make && make install

# Build pico version
echo "  Building pico version..."
make clean
CMAKE_INSTALL_PREFIX="$(pwd)/../build/pico" make pico && make install

cd ..

# Build client
echo "Building client..."
cd client && make && cd ..

# Build server
echo "Building server..."
cd server && make && cd ..

# Copy client binary to server build directory
echo "Copying device.bin to server..."
cp client/build/device.bin server/build/device.bin

echo "OTA project build complete!"

#!/bin/bash

set -e

echo "Building OTA project..."

# Build libota first
echo "Building libota..."
cd libota && make install && cd ..

# Build client
echo "Building client..."
cd client && make && cd ..

# Build server
echo "Building server..."
cd server && make && cd ..

echo "OTA project build complete!"

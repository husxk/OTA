#!/bin/bash

set -e

echo "Cleaning OTA project..."

# Clean libota
echo "Cleaning libota..."
cd libota && make clean && cd ..

# Clean client
echo "Cleaning client..."
cd client && make clean && cd ..

# Clean server
echo "Cleaning server..."
cd server && make clean && cd ..

# Clean main build directory
rm -rf build/

echo "OTA project cleaned!"

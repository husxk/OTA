#!/bin/bash

set -e

INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}"

rm -rf build/
mkdir -p build

cd build
cmake -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" ..
make

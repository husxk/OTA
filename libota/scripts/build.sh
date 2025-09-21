#!/bin/bash

TOP_DIR=$(git rev-parse --show-toplevel)

mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX="$TOP_DIR/build" ..
make

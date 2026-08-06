#!/bin/sh

set -eu

cmake \
   -S . \
   -B build/debug \
   -G Ninja \
   -DCMAKE_BUILD_TYPE=Debug \
   -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake --build build/debug

ctest --test-dir build/debug --output-on-failure


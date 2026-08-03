#!/bin/sh

set -eu

cmake \
   -S . \
   -B build \
   -DCMAKE_BUILD_TYPE=Release \
   -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake --build build


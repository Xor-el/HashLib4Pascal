#!/usr/bin/env bash
# TODO(FPC 3.2.4): remove this shim. FPC 3.2.2 hardcodes libssl.1.1.dylib, so
# symlink Homebrew's OpenSSL 3 dylibs to the 1.1 names on macOS.
set -euo pipefail

OSSL_LIB="$(brew --prefix openssl@3)/lib"
sudo mkdir -p /usr/local/lib
sudo ln -sf "$OSSL_LIB/libssl.3.dylib"    /usr/local/lib/libssl.1.1.dylib
sudo ln -sf "$OSSL_LIB/libcrypto.3.dylib" /usr/local/lib/libcrypto.1.1.dylib

#!/usr/bin/env bash
# FPC 3.2.2 hardcodes libssl.so.1.1; symlink OpenSSL 3.x ELF libraries on Linux/BSD.
set -euo pipefail

ARCH_DIR="${1:-}"
if [ -z "$ARCH_DIR" ] && command -v gcc >/dev/null 2>&1; then
  multiarch="$(gcc -print-multiarch 2>/dev/null || true)"
  if [ -n "$multiarch" ] && [ -f "/usr/lib/$multiarch/libssl.so.3" ]; then
    ARCH_DIR="/usr/lib/$multiarch"
  fi
fi
if [ -z "$ARCH_DIR" ] || [ ! -f "$ARCH_DIR/libssl.so.3" ]; then
  for candidate in \
    /usr/lib/powerpc64-linux-gnu \
    /usr/lib/ppc64-linux-gnu \
    /usr/lib/arm-linux-gnueabihf \
    /usr/lib/aarch64-linux-gnu \
    /usr/lib/x86_64-linux-gnu \
    /usr/lib; do
    if [ -f "$candidate/libssl.so.3" ]; then
      ARCH_DIR="$candidate"
      break
    fi
  done
fi

if [ ! -f "$ARCH_DIR/libssl.so.3" ]; then
  echo "openssl-libssl11-shim-unix: libssl.so.3 not found under $ARCH_DIR" >&2
  exit 1
fi

ln_cmd=(ln -sf)
if [ "${OPENSSL_USE_SUDO:-1}" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    ln_cmd=(sudo ln -sf)
  fi
fi

"${ln_cmd[@]}" "$ARCH_DIR/libssl.so.3"    "$ARCH_DIR/libssl.so.1.1"
"${ln_cmd[@]}" "$ARCH_DIR/libcrypto.so.3" "$ARCH_DIR/libcrypto.so.1.1"

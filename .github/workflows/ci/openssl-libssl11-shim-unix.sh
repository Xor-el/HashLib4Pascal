#!/usr/bin/env bash
# TODO(FPC 3.2.4): remove this shim. FPC 3.2.2 hardcodes libssl.so.1.1, so
# symlink the real OpenSSL 3.x libraries to the 1.1 sonames on Linux/BSD.
# Linux installs libssl.so.3; FreeBSD/DragonFly dports install
# libssl.so.<SHLIBVER> (currently libssl.so.12), so the soname can't be assumed.
set -euo pipefail

ARCH_DIR="${1:-}"

# True if $1 holds a real OpenSSL libssl (any soname except the .1.1 we create).
dir_has_libssl() {
  local d="$1" f
  [ -n "$d" ] || return 1
  for f in "$d"/libssl.so.*; do
    case "$f" in */libssl.so.1.1) continue ;; esac
    [ -e "$f" ] && return 0
  done
  return 1
}

if [ -z "$ARCH_DIR" ] && command -v gcc >/dev/null 2>&1; then
  multiarch="$(gcc -print-multiarch 2>/dev/null || true)"
  if [ -n "$multiarch" ] && dir_has_libssl "/usr/lib/$multiarch"; then
    ARCH_DIR="/usr/lib/$multiarch"
  fi
fi
if [ -z "$ARCH_DIR" ] || ! dir_has_libssl "$ARCH_DIR"; then
  for candidate in \
    /usr/lib/powerpc64-linux-gnu \
    /usr/lib/ppc64-linux-gnu \
    /usr/lib/arm-linux-gnueabihf \
    /usr/lib/aarch64-linux-gnu \
    /usr/lib/x86_64-linux-gnu \
    /usr/lib; do
    if dir_has_libssl "$candidate"; then
      ARCH_DIR="$candidate"
      break
    fi
  done
fi

if ! dir_has_libssl "$ARCH_DIR"; then
  echo "openssl-libssl11-shim-unix: no OpenSSL 3.x libssl.so.* found under ${ARCH_DIR:-<unset>}" >&2
  exit 1
fi

# Resolve the real source lib for a base name, preferring the Linux .so.3 soname
# and otherwise taking the dports-versioned file (e.g. libcrypto.so.12).
find_src() {
  local base="$1" f
  if [ -e "$ARCH_DIR/$base.so.3" ]; then
    printf '%s\n' "$ARCH_DIR/$base.so.3"; return 0
  fi
  for f in "$ARCH_DIR/$base.so."*; do
    case "$f" in */"$base.so.1.1") continue ;; esac
    [ -e "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

ssl_src="$(find_src libssl)"
crypto_src="$(find_src libcrypto)"

ln_cmd=(ln -sf)
if [ "${OPENSSL_USE_SUDO:-1}" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    ln_cmd=(sudo ln -sf)
  fi
fi

"${ln_cmd[@]}" "$ssl_src"    "$ARCH_DIR/libssl.so.1.1"
"${ln_cmd[@]}" "$crypto_src" "$ARCH_DIR/libcrypto.so.1.1"

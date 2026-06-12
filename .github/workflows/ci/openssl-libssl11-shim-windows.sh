#!/usr/bin/env bash
# TODO(FPC 3.2.4): remove this shim. FPC 3.2.2's openssl unit hardcodes the
# OpenSSL 1.1 Windows DLL names, but modern Windows CI runners ship only
# OpenSSL 3.x. Copy the runner's OpenSSL 3 DLLs (already on PATH) to the 1.1
# names FPC expects so the default InitSSLInterface finds them. FPC 3.2.4+
# knows the OpenSSL 3 names directly.
#
# Mirrors openssl-libssl11-shim-unix.sh / -macos.sh, but Windows has no cheap
# symlink, so we copy. We write next to the source DLL (already on PATH) so the
# make binary loads it without us having to mutate the caller's PATH (this runs
# in a subshell and could not export PATH back anyway).
set -euo pipefail

# Bitness matters: FPC 3.2.2 (and OpenSSL 3) use different DLL names per arch.
# 64-bit looks for libssl-1_1-x64.dll (OpenSSL 3 ships libssl-3-x64.dll);
# 32-bit looks for libssl-1_1.dll (OpenSSL 3 ships libssl-3.dll).
# Derive from the FPC target the make binary is compiled for; 
# default to 64-bit (the only Windows CI target).
case "${FPC_TARGET:-}" in
  i386-win32|*-win32|*win32*) SRC_SUFFIX="-3";     DST_SUFFIX="-1_1"     ;;
  *)                          SRC_SUFFIX="-3-x64"; DST_SUFFIX="-1_1-x64" ;;
esac

# Find $1$SRC_SUFFIX.dll on PATH and copy it to the $1$DST_SUFFIX.dll FPC wants.
copy_alias() {
  local base="$1" src="" dir
  local IFS=':'
  for dir in $PATH; do
    if [ -f "$dir/$base$SRC_SUFFIX.dll" ]; then
      src="$dir/$base$SRC_SUFFIX.dll"
      break
    fi
  done
  if [ -z "$src" ]; then
    echo "openssl-libssl11-shim-windows: $base$SRC_SUFFIX.dll not found on PATH" >&2
    return 1
  fi
  cp -f "$src" "$(dirname "$src")/$base$DST_SUFFIX.dll"
  echo "openssl-libssl11-shim-windows: $src -> $(dirname "$src")/$base$DST_SUFFIX.dll"
}

copy_alias libssl
copy_alias libcrypto

#!/bin/sh
set -eu

# 11.4-gcc images install GCC under /usr/gcc/<ver>/bin (not always as cc on PATH).
_path="/opt/csw/bin:/usr/local/bin"
if [ -d /usr/gcc ]; then
  for _gcc_bin in /usr/gcc/*/bin; do
    if [ -d "$_gcc_bin" ]; then
      _path="$_gcc_bin:$_path"
      break
    fi
  done
fi
export PATH="$_path"
unset _path _gcc_bin

pkgutil -y -i bash curl git gmake

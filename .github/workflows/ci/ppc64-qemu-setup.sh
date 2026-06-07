#!/usr/bin/env bash
set -euo pipefail

docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
if ! ls /proc/sys/fs/binfmt_misc/qemu-ppc64* >/dev/null 2>&1; then
  echo "::error::qemu-ppc64 binfmt handler not registered"
  ls /proc/sys/fs/binfmt_misc/
  exit 1
fi

#!/usr/bin/env bash
set -euo pipefail

# Register the ppc64 (big-endian) binfmt handler on the runner host so that
# `docker run --platform linux/ppc64 ...` (ppc64-be-build.sh) transparently
# executes big-endian binaries under QEMU user-mode.
#
# We install QEMU from the Ubuntu runner's apt (qemu-user-static, currently
# ~8.2) rather than multiarch/qemu-user-static (abandoned at 7.2.0) or
# tonistiigi/binfmt (little-endian ppc64le only). The package's postinst
# registers each handler with the F (fix-binary) flag via update-binfmts, so
# the interpreter fd is preserved into the container and qemu does not need to
# exist inside the rootfs. See ppc64-be-images.env for the rationale.

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq qemu-user-static binfmt-support

# Idempotent: enable the handler in case it was installed but left disabled.
sudo update-binfmts --enable qemu-ppc64 2>/dev/null || true

BINFMT_FILE=/proc/sys/fs/binfmt_misc/qemu-ppc64
if [ ! -e "$BINFMT_FILE" ]; then
  echo "::error::qemu-ppc64 binfmt handler not registered"
  ls /proc/sys/fs/binfmt_misc/ || true
  exit 1
fi

echo "qemu-ppc64-static: $(qemu-ppc64-static --version 2>/dev/null | head -1 || echo 'unknown')"
echo "binfmt handler ${BINFMT_FILE}:"
cat "$BINFMT_FILE"

# F (fix-binary) is required so the interpreter works inside the container.
if ! grep -q 'flags:.*F' "$BINFMT_FILE"; then
  echo "::error::qemu-ppc64 binfmt flags missing F (fix-binary mode); got:" >&2
  cat "$BINFMT_FILE" >&2
  exit 1
fi

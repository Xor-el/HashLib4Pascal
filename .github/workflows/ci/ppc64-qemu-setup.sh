#!/usr/bin/env bash
set -euo pipefail

# Register the ppc64 (big-endian) binfmt handler on the runner host so that
# `docker run --platform linux/ppc64 ...` (ppc64-be-build.sh) transparently
# executes big-endian binaries under QEMU user-mode.
#
# We install QEMU from the Ubuntu runner's apt rather than
# multiarch/qemu-user-static (abandoned at 7.2.0) or tonistiigi/binfmt
# (little-endian ppc64le only). Older images ship qemu-user-static, which
# registers each handler with the F (fix-binary) flag via update-binfmts; newer
# ones replace it with qemu-user (static binaries) plus qemu-user-binfmt, which
# installs binfmt.d entries (also with F) for systemd-binfmt to load. With F
# the interpreter fd is preserved into the container, so qemu does not need to
# exist inside the rootfs. See ppc64-be-images.env for the rationale.

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
if apt-cache policy qemu-user-static | grep -q 'Candidate: [^(]'; then
  sudo apt-get install -y -qq qemu-user-static binfmt-support
else
  sudo apt-get install -y -qq qemu-user qemu-user-binfmt binfmt-support
fi

# Idempotent: enable the handler in case it was installed but left disabled.
sudo update-binfmts --enable qemu-ppc64 2>/dev/null || true

BINFMT_FILE=/proc/sys/fs/binfmt_misc/qemu-ppc64
# qemu-user-binfmt only drops binfmt.d entries; load them if nothing registered yet.
if [ ! -e "$BINFMT_FILE" ]; then
  sudo systemctl restart systemd-binfmt 2>/dev/null || true
fi
if [ ! -e "$BINFMT_FILE" ]; then
  echo "::error::qemu-ppc64 binfmt handler not registered"
  ls /proc/sys/fs/binfmt_misc/ || true
  exit 1
fi

QEMU_PPC64="$(command -v qemu-ppc64-static || command -v qemu-ppc64 || true)"
echo "${QEMU_PPC64:-qemu-ppc64}: $("${QEMU_PPC64:-qemu-ppc64}" --version 2>/dev/null | head -1 || echo 'unknown')"
echo "binfmt handler ${BINFMT_FILE}:"
cat "$BINFMT_FILE"

# F (fix-binary) is required so the interpreter works inside the container.
if ! grep -q 'flags:.*F' "$BINFMT_FILE"; then
  echo "::error::qemu-ppc64 binfmt flags missing F (fix-binary mode); got:" >&2
  cat "$BINFMT_FILE" >&2
  exit 1
fi

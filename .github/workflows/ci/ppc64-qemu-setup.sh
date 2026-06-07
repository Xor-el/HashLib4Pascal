#!/usr/bin/env bash
set -euo pipefail

CI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ppc64-be-images.env
source "$CI_ROOT/ppc64-be-images.env"

docker run --rm --privileged \
  "$PPC64_QEMU_REGISTER_IMAGE" \
  --reset -p yes -c yes

if ! ls /proc/sys/fs/binfmt_misc/qemu-ppc64* >/dev/null 2>&1; then
  echo "::error::qemu-ppc64 binfmt handler not registered"
  ls /proc/sys/fs/binfmt_misc/
  exit 1
fi

BINFMT_FILE="$(ls /proc/sys/fs/binfmt_misc/qemu-ppc64* | head -1)"
echo "binfmt handler ${BINFMT_FILE}:"
cat "$BINFMT_FILE"

if ! grep -q 'flags:.*F' "$BINFMT_FILE"; then
  echo "::error::qemu-ppc64 binfmt flags missing F (fix-binary mode); got:" >&2
  cat "$BINFMT_FILE" >&2
  exit 1
fi

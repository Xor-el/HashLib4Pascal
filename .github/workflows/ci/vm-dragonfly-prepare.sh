#!/bin/sh
set -eu

# shellcheck source=shared/common.sh
. "$(cd "$(dirname "$0")" && pwd)/shared/common.sh"
ci_init_paths

pkg install -y bash curl git gmake openssl

for h in github.com packages.lazarus-ide.org downloads.freepascal.org; do
  ip=$(drill "$h" 2>/dev/null | awk '/^'"$h"'/{print $5; exit}')
  if [ -n "$ip" ]; then
    echo "$ip $h" >> /etc/hosts
  fi
done

OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" /usr/local/lib

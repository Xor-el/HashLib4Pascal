#!/bin/sh
set -eu

# Runs under the VM's /bin/sh, so resolve CI_ROOT from $0 rather than sourcing
# common.sh (which targets bash, e.g. BASH_SOURCE / set -o pipefail).
CI_ROOT="$(cd "$(dirname "$0")" && pwd)"

pkg install -y bash curl git gmake openssl

# TODO(dragonfly-dns): remove once the DragonFlyBSD VM image has reliable DNS.
# Resolution of the package/source mirrors intermittently fails inside the VM,
# so pre-resolve them with drill and pin the result in /etc/hosts. Best-effort:
# a lookup miss leaves the host unpinned rather than failing the job.
for h in github.com packages.lazarus-ide.org downloads.freepascal.org; do
  ip=$(drill "$h" 2>/dev/null | awk '/^'"$h"'/{print $5; exit}')
  if [ -n "$ip" ]; then
    echo "$ip $h" >> /etc/hosts
  fi
done

# TODO(FPC 3.2.4): drop the OpenSSL 1.1 shim once FPC links against OpenSSL 3.
OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" /usr/local/lib

#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "warning: scripts/test-linux.sh is intended to run inside the Linux Docker container" >&2
fi

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true
fi

if [[ ! -w /sys/fs/cgroup ]]; then
    echo "warning: /sys/fs/cgroup is not writable; cgroup integration tests may fail" >&2
fi

go generate ./pkg/filter/...

if [[ "$#" -eq 0 ]]; then
    set -- ./...
fi

go test -v -count=1 "$@"

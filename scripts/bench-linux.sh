#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "warning: scripts/bench-linux.sh is intended to run inside the Linux Docker container" >&2
fi

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true
fi

go generate ./pkg/filter/...

pkg="${1:-./...}"
if [[ "$#" -gt 0 ]]; then
    shift
fi

go test -run '^$' -bench "${BENCH:-.}" -benchmem -count "${COUNT:-5}" "$pkg" "$@"

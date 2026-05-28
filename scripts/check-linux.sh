#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "warning: scripts/check-linux.sh is intended to run inside the Linux Docker container" >&2
fi

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true
fi

if [[ ! -w /sys/fs/cgroup ]]; then
    echo "warning: /sys/fs/cgroup is not writable; cgroup integration tests may fail" >&2
fi

unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
    echo "gofmt needed:" >&2
    echo "$unformatted" >&2
    exit 1
fi

go generate ./pkg/filter/...
go vet ./...
go test -race -count=1 ./...

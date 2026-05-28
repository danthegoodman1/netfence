# AGENTS.md

## Testing And Benchmarks

This project depends on Linux-only behavior, cgroups, eBPF, and privileged
networking. Do not treat macOS host test or benchmark results as production
evidence for those paths.

Use the Docker Linux gate for validation:

- `make check-docker`
- `make test-docker`
- `make test-docker-cgroup`
- `make test-docker-tc`
- `make bench-docker`

For targeted benchmarks or test runs, use the Docker compose `bench`/`test`
services rather than running Linux/eBPF-sensitive commands directly on the Mac
host. macOS-local `go test` is fine only as a quick compile/unit sanity check
for packages that are not exercising Linux-only behavior.

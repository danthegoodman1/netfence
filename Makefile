# Makefile for superebpf

.PHONY: all generate build test test-docker clean help

# Default target
all: generate build

# Generate BPF objects from C source
generate:
	@echo "Generating BPF objects..."
	go generate ./pkg/filter/...

# Build the project
build: generate
	@echo "Building..."
	go build ./...

# Run tests locally (requires Linux with root)
test:
	@echo "Running tests..."
	sudo go test -v ./tests/integration/...

# Run tests in Docker (works on Mac and Linux)
test-docker:
	@echo "Running tests in Docker..."
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Run only cgroup filter tests in Docker
test-docker-cgroup:
	@echo "Running cgroup tests in Docker..."
	docker compose -f docker-compose.test.yml --profile cgroup up --build --abort-on-container-exit test-cgroup

# Run only TC filter tests in Docker
test-docker-tc:
	@echo "Running TC tests in Docker..."
	docker compose -f docker-compose.test.yml --profile tc up --build --abort-on-container-exit test-tc

# Clean generated files and build artifacts
clean:
	@echo "Cleaning..."
	rm -f pkg/filter/*_bpfel.go pkg/filter/*_bpfeb.go
	rm -f pkg/filter/*.o
	go clean ./...

# Update dependencies
deps:
	go mod tidy

# Lint the code
lint:
	@echo "Linting..."
	go vet ./...
	@if command -v staticcheck > /dev/null; then staticcheck ./...; fi

# Format the code
fmt:
	go fmt ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  all              - Generate BPF objects and build (default)"
	@echo "  generate         - Generate BPF objects from C source"
	@echo "  build            - Build the project"
	@echo "  test             - Run tests locally (requires Linux + root)"
	@echo "  test-docker      - Run tests in Docker (Mac + Linux)"
	@echo "  test-docker-cgroup - Run only cgroup filter tests in Docker"
	@echo "  test-docker-tc   - Run only TC filter tests in Docker"
	@echo "  clean            - Clean generated files and build artifacts"
	@echo "  deps             - Update dependencies"
	@echo "  lint             - Lint the code"
	@echo "  fmt              - Format the code"
	@echo "  help             - Show this help"

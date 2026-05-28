FROM golang:1.25.5-trixie

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bpftool \
        ca-certificates \
        clang \
        gcc \
        iproute2 \
        iptables \
        iputils-ping \
        libbpf-dev \
        libc6-dev \
        libsqlite3-dev \
        linux-libc-dev \
        llvm \
        make \
        netcat-openbsd \
        pkg-config \
        procps \
        sqlite3 \
        util-linux \
    && ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm \
    && mkdir -p /workspace /go/pkg/mod /root/.cache/go-build \
    && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1 \
    CPATH=/usr/include \
    GOFLAGS=-buildvcs=false

WORKDIR /workspace

CMD ["bash"]

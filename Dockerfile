# Dockerfile for Shadow + leansim on ARM64 (aarch64)
# Build context must be the parent directory containing both `leansim/` and `shadow/`:
#   cd /Users/taisei/dev && docker build -f leansim/Dockerfile -t leansim-shadow .

FROM ubuntu:24.04

ENV CARGO_TERM_COLOR=always
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies for Shadow + leansim
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    findutils \
    gcc \
    g++ \
    make \
    pkg-config \
    libclang-dev \
    libglib2.0-0 \
    libglib2.0-dev \
    libc-dbg \
    netbase \
    python3 \
    python3-networkx \
    python3-yaml \
    xz-utils \
    util-linux \
    curl \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain (shared for both Shadow and leansim)
# Shadow pins 1.95; leansim works with it too
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain 1.95 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy Shadow source and build it
COPY shadow/ /root/shadow/
WORKDIR /root/shadow
# --test/--extra skipped: x86-specific assembly; extra_tests target unavailable
RUN ./setup build && ./setup install

# Copy leansim source and build it
COPY leansim/ /root/leansim/
WORKDIR /root/leansim
RUN cargo build --release

# Verify both binaries exist
RUN ~/.local/bin/shadow --version && \
    /root/leansim/target/release/leansim --version

WORKDIR /root/leansim

# Entrypoint: generate Shadow config, run simulation, optionally generate netviz trace
COPY leansim/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

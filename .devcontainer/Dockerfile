# Use a specific version of Alpine for better reproducibility
FROM mcr.microsoft.com/vscode/devcontainers/base:alpine-3.21

# Set environment variables for rustup and cargo directories
# This makes them available globally in the container's PATH
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install necessary packages:
# - curl: to download rustup-init.sh
# - bash: rustup-init.sh is a bash script
# - build-base: provides essential build tools like gcc, g++, make
# - git: for cloning repositories and dependency management
# - gdb: a common debugger
# - rust-analyzer: the language server for Rust (installed via rustup later)
# - nano: a simple text editor (optional, can replace with vim etc.)
# - openssl-dev, zlib-dev, etc.: Common development libraries often needed by Rust crates
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
    curl \
    bash \
    build-base \
    git \
    gdb \
    nano \
    # openssl-dev \
    zlib-dev \
    # Add more dev libraries here if your projects need them (e.g., libpq-dev for postgres, sqlite-dev, etc.)
    && \
    # Install rustup
    # We use sh -s -- -y to run the script non-interactively and accept defaults.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    # Add rust-analyzer component (now that rustup is in PATH)
    rustup component add rust-analyzer && \
    # Clean up APK cache to reduce image size
    rm -rf /var/cache/apk/*

# Set the working directory inside the container
WORKDIR /workspaces

# (Optional) Set the default command when the container starts
# CMD ["bash"]
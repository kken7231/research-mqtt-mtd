## -----------------------------------------------
## builder rust alpine
## -----------------------------------------------
FROM rust:1.86-alpine AS builder

# prepare packages for crosscompile
RUN apk add --no-cache musl-dev gcc
RUN rustup target add aarch64-unknown-linux-musl

# copy necessary files
# all modules stated in the root Cargo.toml are needed, not just server tasks
RUN mkdir -p /rust-mqttmtd
WORKDIR /rust-mqttmtd
COPY ./rust-mqttmtd/ /rust-mqttmtd

# build authserver & mqttinterface
RUN CC=gcc RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --package testing --package mqttmtd-authserver --package mqttinterface --target aarch64-unknown-linux-musl

## -----------------------------------------------
## runner alpine
## -----------------------------------------------
FROM alpine:3.21 AS runner

# install tcpdump, mosquitto and dumb-init
RUN apk update && apk upgrade
RUN apk add --no-cache tcpdump mosquitto dumb-init

# copy entrypoint shellscript
COPY ./mqttmtd-layer/entrypoint.sh /entrypoint.sh

# copy authserver, mqttinterface and testing
COPY --from=builder /rust-mqttmtd/target/aarch64-unknown-linux-musl/release/mqttmtd-authserver /mqttmtd/bin/
COPY --from=builder /rust-mqttmtd/target/aarch64-unknown-linux-musl/release/mqttinterface /mqttmtd/bin/
COPY --from=builder /rust-mqttmtd/target/aarch64-unknown-linux-musl/release/testing /mqttmtd/bin/

# copy confs
COPY ./mqttmtd-layer/conf /mqttmtd/conf

# copy acl
COPY ./mqttmtd-layer/acl.yaml /mqttmtd/acl.yaml

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
  CMD test -f /mqttmtd/server_ready || exit 1

ENTRYPOINT ["dumb-init", "--", "/bin/sh", "/entrypoint.sh"]
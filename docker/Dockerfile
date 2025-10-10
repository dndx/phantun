#
# Dockerfile for phantun
#

#
# Build stage
#
FROM rust:1.90.0-trixie AS builder

WORKDIR /phantun

COPY . .

RUN cargo build --release && \
    strip target/release/client target/release/server

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq libcap2-bin && \
    setcap "cap_net_admin=+ep" target/release/client "cap_net_admin=+ep" target/release/server

#
# Runtime stage
#
FROM debian:trixie-20250929-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq gosu iproute2 iptables && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -u 1001 phantun

COPY --from=builder /phantun/target/release/client /usr/local/bin/phantun-client
COPY --from=builder /phantun/target/release/server /usr/local/bin/phantun-server
COPY docker/phantun.sh /usr/local/bin/

ENV USE_IPTABLES_NFT_BACKEND=0
ENV RUST_LOG=info

ENTRYPOINT ["phantun.sh"]
CMD ["phantun-server", "--help"]

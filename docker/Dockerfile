#
# Dockerfile for phantun
#

#
# Build stage
#
FROM rust:alpine AS builder

ARG VERSION=v0.6.0
RUN apk update \
  && apk add --no-cache --virtual .build-deps git musl-dev \
  && git clone https://github.com/dndx/phantun.git --branch $VERSION \
  && cd phantun \
  && git checkout $VERSION \
  && cargo build --release \
  && strip target/release/server target/release/client \
  && install target/release/server /usr/local/bin/phantun-server \
  && install target/release/client /usr/local/bin/phantun-client \
  && cd - \
  && rm -r phantun \
  && apk del .build-deps \
  && rm -rf /var/cache/apk/*

#
# Runtime stage
#
FROM alpine:3.16
LABEL maintainer="pexcn <i@pexcn.me>"

RUN apk update \
  && apk add --no-cache iptables ip6tables tzdata \
  && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/bin/phantun-server /usr/local/bin/
COPY --from=builder /usr/local/bin/phantun-client /usr/local/bin/
COPY phantun.sh /usr/local/bin/

ENTRYPOINT ["phantun.sh"]
CMD ["phantun-server", "--help"]

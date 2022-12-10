#
# Dockerfile for phantun
#

#
# Build stage
#
FROM rust:alpine AS builder

COPY . /phantun

RUN apk update \
  && apk add --no-cache --virtual .build-deps musl-dev \
  && cd phantun \
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

RUN apk update \
  && apk add --no-cache iptables ip6tables tzdata \
  && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/bin/phantun-server /usr/local/bin/
COPY --from=builder /usr/local/bin/phantun-client /usr/local/bin/
COPY docker/phantun.sh /usr/local/bin/

ENTRYPOINT ["phantun.sh"]
CMD ["phantun-server", "--help"]

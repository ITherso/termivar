# syntax=docker/dockerfile:1

FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/termivar

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    perl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/termivar/target \
    cargo build --locked --release -p termivar-cli \
    && cp target/release/termivar /tmp/termivar \
    && strip /tmp/termivar

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 termivar \
    && useradd --uid 1000 --gid termivar --create-home termivar

WORKDIR /app

COPY --from=builder --chown=termivar:termivar /tmp/termivar /usr/local/bin/termivar

RUN mkdir -p /app/.termivar && chown -R termivar:termivar /app

USER termivar

ENTRYPOINT ["termivar"]
CMD ["--help"]

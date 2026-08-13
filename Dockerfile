# syntax=docker/dockerfile:1

FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/venom

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    perl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/venom/target \
    cargo build --locked --release -p venom-cli \
    && cp target/release/venom /tmp/venom \
    && strip /tmp/venom

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 venom \
    && useradd --uid 1000 --gid venom --create-home venom

WORKDIR /app

COPY --from=builder --chown=venom:venom /tmp/venom /usr/local/bin/venom

RUN mkdir -p /app/.venom && chown -R venom:venom /app

USER venom

ENTRYPOINT ["venom"]
CMD ["--help"]

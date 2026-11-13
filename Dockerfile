FROM rust:1.98.1-bookworm AS build
WORKDIR /source
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked -p suba

FROM scratch AS binary
COPY --from=build /source/target/release/suba /suba

FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates libssl3 gosu tzdata && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/config /app/data && chown -R 10001:10001 /app
COPY --from=build /source/target/release/suba /usr/local/bin/suba
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV HOST=0.0.0.0 PORT=8090 CONFIG=/app/config DATA=/app/data PUID=10001 PGID=10001 TZ=Etc/UTC
WORKDIR /app
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []

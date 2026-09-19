FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir /data && chown 65532:65532 /data
COPY --from=build /src/target/release/keygate /usr/local/bin/keygate
USER 65532:65532
WORKDIR /data
ENV KEYGATE_MANAGER_LISTEN=0.0.0.0:8080 KEYGATE_AUTHZ_LISTEN=0.0.0.0:8081
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/keygate"]

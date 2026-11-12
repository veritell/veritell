# Build: docker build -t veritell .
# Run:   docker run -p 8443:8443 -v "$PWD/certs:/certs:ro" -e VERITELL_SECRET=... veritell \
#          --upstream host.docker.internal:8080
FROM rust:1-bookworm AS build
# BoringSSL (pulled in by Pingora) needs cmake and a C/C++ toolchain; bindgen needs libclang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The gateway embeds the probe scripts at compile time.
COPY probe/probe.js probe/behavior.js ./probe/
RUN cargo build --release --locked -p veritell-proxy

FROM debian:bookworm-slim
# CA roots, so --upstream-tls can verify origins with public certificates.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --shell /usr/sbin/nologin veritell
COPY --from=build /src/target/release/veritell /usr/local/bin/veritell
USER veritell
EXPOSE 8443
ENTRYPOINT ["veritell", "--listen", "0.0.0.0:8443", "--cert", "/certs/cert.pem", "--key", "/certs/key.pem"]

# Container image for example.hopme.sh — a `hops://` demo (DESIGN.md §30).
#
# It bundles two binaries and runs both:
#   - hop-example-origin : a tiny HTTP backend on localhost:8080 (the "origin")
#   - hop-endpoint       : the listening Hop node that translates hops:// → that origin,
#                          bound to the single domain it's authorized for (--domain)
#
# So a client speaking hops://example.hopme.sh reaches the endpoint over the mesh; the
# endpoint validates the signed host == example.hopme.sh and fetches ONLY localhost:8080.
#
# Build context is the repo root:
#   docker build -f services/hop-endpoint/Dockerfile -t hop-example .

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY services ./services
COPY examples ./examples
RUN cargo build --release -p hop-endpoint -p hop-example-origin

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hop-endpoint /usr/local/bin/hop-endpoint
COPY --from=build /src/target/release/hop-example-origin /usr/local/bin/hop-example-origin
COPY services/hop-endpoint/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Cloud Run sets $PORT (the endpoint's WebSocket bearer). HOP_* come from the Cloud Run
# env (see infra/cloud_run.tf). The origin always sits on localhost:8080.
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

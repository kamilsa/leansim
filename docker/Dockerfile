# syntax=docker/dockerfile:1
# Builds leansim onto a Shadow-capable arm64 image. shadow-sim.py owns invocation.
ARG SHADOW_IMAGE=kamilsa/shadow-arm:latest

FROM --platform=linux/arm64 rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM --platform=linux/arm64 ${SHADOW_IMAGE}
COPY --from=build /src/target/release/leansim /opt/leansim/leansim

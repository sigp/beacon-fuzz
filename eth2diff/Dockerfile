FROM ubuntu:18.04 as build

ARG RUST_TOOLCHAIN="nightly"

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"

# Update ubuntu
# Install dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		build-essential \
		ca-certificates \
		curl \
		git

# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN"

# create a new empty shell project
RUN USER=root cargo new --bin eth2diff
WORKDIR /eth2diff

# copy over your manifests
# COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# Copy your source tree
COPY ./src ./src

# Build the CLI tool
RUN rm ./target/release/deps/eth2diff*
RUN cargo +nightly build --release --out-dir=. -Z unstable-options

FROM ubuntu:18.04

# Install libssl
RUN apt-get update && apt-get install -y libssl-dev

# COPY --from=build shared .
COPY --from=build /eth2diff/eth2diff .

ENTRYPOINT ["./eth2diff"]
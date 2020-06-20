FROM ubuntu:18.04 AS build

ARG RUST_TOOLCHAIN="nightly"
ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"

ARG GIT_BRANCH="master"
ARG PRESET="mainnet"

# Update ubuntu
# Install dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		build-essential \
		pkg-config \
		libssl-dev \
		ca-certificates \
		curl \
		git

# Install Rust and Cargo
RUN curl --proto '=https' \
	--tlsv1.2 \
	-sSf https://sh.rustup.rs | sh -s -- -y \
	--default-toolchain "$RUST_TOOLCHAIN"

WORKDIR /app

RUN git clone \
	--branch "$GIT_BRANCH" \
	--recursive \
	--depth 1 \
	https://github.com/sigp/lighthouse

RUN cd lighthouse && \
	# Build lcli in release mode
	cargo install --path lcli --locked

#
# Exporting compiled binaries 
#
FROM scratch AS export

# Copy over the CLI from the build phase
COPY --from=build /app/lighthouse/target/release/lcli .

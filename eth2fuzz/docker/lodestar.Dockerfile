FROM ubuntu:18.04 AS build

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

WORKDIR /eth2fuzz

# Copy all
COPY . .

# Build the CLI tool
RUN make -f eth2fuzz.mk build

#####################################
############ Lodestar ###############

FROM ubuntu:18.04

ARG LODESTAR_VERSION="0.13.0"
ARG DISCV5_VERSION="0.5.0"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		software-properties-common \
		curl \
		gpg-agent \
		git

# Install nodejs
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash

# Install npm & nodejs
RUN apt-get update && \
	apt-get install -y \
	nodejs


WORKDIR /eth2fuzz

# Install lodestar
RUN npm i "@chainsafe/lodestar-types@$LODESTAR_VERSION"
RUN npm i "@chainsafe/discv5@$DISCV5_VERSION"

# Install Javascript fuzzer
RUN npm i -g jsfuzz

#####################################
############ eth2fuzz ###############

# COPY --from=build shared .
COPY --from=build /eth2fuzz/eth2fuzz .

# Set env for eth2fuzz target listing
ENV CURRENT_CLIENT="LODESTAR"

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]

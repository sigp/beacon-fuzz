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
RUN make build

#####################################
############ Lodestar ###############

FROM ubuntu:18.04

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

#####################################
############ eth2fuzz ###############

WORKDIR /eth2fuzz

# COPY --from=build shared .
COPY --from=build /eth2fuzz/eth2fuzz .

############ Lodestar ###############

# Install lodestar
RUN npm i @chainsafe/lodestar-types @chainsafe/discv5

# Install Javascript fuzzer
RUN npm i -g jsfuzz

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]
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

#####################################
############ lighthouse #################

# Install dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		pkg-config \
		libssl-dev

# Clone lighthouse
RUN git clone \
	--branch "master" \
	--recursive \
	--depth 1 \
	https://github.com/sigp/lighthouse

#####################################
############ nimbus #################

ARG NIMBUS_GIT_BRANCH="devel"
ARG PRESET="mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		cmake \
		libpcre3-dev \
		clang

# Clone the project
RUN git clone \
	--branch "$NIMBUS_GIT_BRANCH" \
	--recursive \
 	--depth 1 \
	https://github.com/status-im/nim-beacon-chain

WORKDIR nim-beacon-chain

# Build nimbus
RUN make libnfuzz.so libnfuzz.a

#####################################
############ eth2fuzz ###############

WORKDIR /beacon-fuzz/beaconfuzz_v2

# Copy all
COPY . .

# Build the CLI tool
RUN make build

ENTRYPOINT ["/beacon-fuzz/beaconfuzz_v2/beaconfuzz_v2"]
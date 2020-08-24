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
############ nimbus #################

FROM ubuntu:18.04

ARG NIMBUS_GIT_BRANCH="devel"
ARG NIMUTIL_GIT_BRANCH="master"
ARG PRESET="mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		cmake \
		build-essential \
		git \
		libpcre3-dev \
		clang

# Clone the nim-testutils fuzzers
RUN git clone \
	--branch "$NIMUTIL_GIT_BRANCH" \
	--recursive \
	https://github.com/status-im/nim-testutils

RUN cd nim-testutils && git checkout 1601894ec1fd1c7095d405eb0c846cac212fb18f

# Clone the project
RUN git clone \
	--branch "$NIMBUS_GIT_BRANCH" \
	--recursive \
 	--depth 1 \
	https://github.com/status-im/nim-beacon-chain

WORKDIR nim-beacon-chain

# Build nimbus
RUN make

#####################################
############ eth2fuzz ###############

WORKDIR /eth2fuzz

# COPY --from=build shared .
COPY --from=build /eth2fuzz/eth2fuzz .

# Set env for eth2fuzz target listing
ENV CURRENT_CLIENT="NIMBUS"

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]

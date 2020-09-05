FROM ubuntu:18.04 AS build

ARG RUST_TOOLCHAIN="nightly"
ARG GIT_BRANCH="v0.2.7"

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"

# Update ubuntu
# Install dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		build-essential \
		pkg-config \
		libssl-dev \
		ca-certificates \
		curl \
		git \
		build-essential \
		libtool-bin \
		python3-dev \
		automake \
		flex \
		bison \
		libglib2.0-dev \
		libpixman-1-dev \
		clang \
		python3-setuptools \
		llvm \
		binutils-dev \
		libunwind-dev \
		libblocksruntime-dev \
		cmake

# Install Rust and Cargo
RUN curl --proto '=https' \
	--tlsv1.2 \
	-sSf https://sh.rustup.rs | sh -s -- -y \
	--default-toolchain "$RUST_TOOLCHAIN"

# Clone lighthouse
RUN git clone \
	--branch "$GIT_BRANCH" \
	--recurse-submodules \
	--depth 1 \
	https://github.com/sigp/lighthouse

# build lighthouse
RUN cd lighthouse && make

#####################################
############ FUZZERS ################

# Install Rust fuzzer
RUN cargo install honggfuzz
RUN cargo install cargo-fuzz
RUN cargo install afl

#####################################
############ eth2fuzz ################

WORKDIR /eth2fuzz

# Copy all
COPY . .

# Build the CLI tool
RUN make -f eth2fuzz.mk build

# Set env for eth2fuzz target listing
ENV CURRENT_CLIENT="LIGHTHOUSE"

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]

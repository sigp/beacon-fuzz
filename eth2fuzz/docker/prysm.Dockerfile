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
############ prysm #################

FROM ubuntu:18.04

ARG GIT_BRANCH="master"
ARG PRESET="preset_mainnet"
ARG PRYSM_VERSION="v1.0.0-alpha.23"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		software-properties-common \
		curl \
		git \
		clang

# Install golang
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update && \
	apt-get install -y \
	golang

# Install Bazel
RUN curl https://bazel.build/bazel-release.pub.gpg | \
	apt-key add -
RUN echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt-get update && \
	apt-get install -y \
		cmake \
		git \
		bazel \
 		bazel-3.7.0


WORKDIR /eth2fuzz

ENV GOPATH="/eth2fuzz"

# Install prysm
# (Hacky way to get specific version in GOPATH mode)
RUN mkdir -p /eth2fuzz/src/github.com/prysmaticlabs/
RUN cd /eth2fuzz/src/github.com/prysmaticlabs/ && \
    git clone --branch "$GIT_BRANCH" \
    --recurse-submodules \
    --depth 1 \
    https://github.com/prysmaticlabs/prysm
RUN go get github.com/herumi/bls-eth-go-binary/bls

# Install go-fuzz 114
RUN go get -u github.com/mdempsky/go114-fuzz-build

# Build prysm with bazel
RUN cd /eth2fuzz/src/github.com/prysmaticlabs/prysm/ && bazel build

#####################################
############ eth2fuzz ###############

# COPY --from=build shared .
COPY --from=build /eth2fuzz/eth2fuzz .

# Set env for eth2fuzz target listing
ENV CURRENT_CLIENT="PRYSM"

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]

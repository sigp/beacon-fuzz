FROM ubuntu:18.04

# docker hardcoded sh...
SHELL ["/bin/bash", "-c"]

# lighthouse args
ARG RUST_TOOLCHAIN="nightly"
ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"
ARG LIGHTHOUSE_GIT_BRANCH="master"
ARG LIGHTHOUSE_PRESET="mainnet"

# nimbus
ARG NIMBUS_GIT_BRANCH="master"
## devel"
ARG NIMBUS_PRESET="mainnet"

# prysm
ARG PRYSM_GIT_BRANCH="master"
ARG PRYSM_PRESET="preset_mainnet"

# teku
ARG TEKU_GIT_BRANCH="master"
ARG TEKU_PRESET="preset_mainnet"

# zcli
ARG ZCLI_GIT_BRANCH="master"
ARG ZCLI_PRESET="preset_mainnet"


# ALL - Update ubuntu dependencies
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		build-essential \
		pkg-config \
		libssl-dev \
		ca-certificates \
		software-properties-common \
		curl \
		cmake \
		git \
		libpcre3-dev \
		unzip \
		clang \
		binutils-dev \
		libunwind-dev \
		libblocksruntime-dev \
		libtool-bin \
		python3 \
		automake \
		bison \
		libglib2.0-dev \
		libpixman-1-dev \
		python-setuptools \
		openjdk-11-jdk \
		gpg-agent \
		llvm

RUN apt-get update && \
	apt-get install -y \
	npm

# prysm & zcli - Install Golang
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
	golang

# prysm - Install Bazel
# maybe not needed for eth2fuzz
RUN curl https://bazel.build/bazel-release.pub.gpg | \
	apt-key add -
RUN echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		bazel \
		bazel-3.0.0

# lighthouse - Install Rust and Cargo
RUN curl --proto '=https' \
	--tlsv1.2 \
	-sSf https://sh.rustup.rs | sh -s -- -y \
	--default-toolchain "$RUST_TOOLCHAIN"


#####################################
############ FUZZERS ################

# install Javascript fuzzer

RUN npm i -g jsfuzz 

# install Rust fuzzer

RUN cargo install honggfuzz
RUN cargo install cargo-fuzz
RUN cargo install afl

#####################################
############ NIMBUS ################

# Clone the project
RUN git clone \
	--branch "$NIMBUS_GIT_BRANCH" \
 	--depth 1 \
	https://github.com/status-im/nim-beacon-chain

WORKDIR nim-beacon-chain

# First `make` invocation
# will update all Git submodules
RUN make


WORKDIR /eth2fuzz

#####################################
############ LODESTAR ################

# lodestar - Installation using npm
RUN npm i @chainsafe/lodestar-types @chainsafe/discv5


#####################################
############ eth2fuzz ################

# Copy all
COPY . .

# Build the CLI tool
RUN make build




# ENTRYPOINT ["tail", "-f", "/dev/null"]
ENTRYPOINT ["./eth2fuzz"]


# Compilation:
#	DOCKER_BUILDKIT=1 docker build . -t eth2fuzz

# Run the container
#	docker run -it -v `pwd`/workspace:/eth2fuzz/workspace eth2fuzz list
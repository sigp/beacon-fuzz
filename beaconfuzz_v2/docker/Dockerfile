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

WORKDIR /

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
	https://github.com/status-im/nimbus-eth2

WORKDIR /nimbus-eth2

# Build nimbus
RUN NIMFLAGS="-d:disableLTO" make libnfuzz.so libnfuzz.a

#####################################
############ prysm #################

WORKDIR /prysm

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		software-properties-common \
		curl \
		git \
		gpg-agent \
		build-essential \
		pkg-config \
		libssl-dev \
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
		bazel \
 		bazel-3.7.0

# Copy all
COPY libs/pfuzz /prysm/pfuzz/

# Setup golang path
ENV GOPATH="/prysm"

# Get all golang dependencies
# RUN cd /prysm/ && go get -u github.com/prysmaticlabs/prysm || true

# Build prysm with bazel
# RUN cd /prysm/src/github.com/prysmaticlabs/prysm/ && bazel build

# Compile pfuzz lib
# RUN cd /prysm/pfuzz/ && go get . || true
# RUN cd /prysm/pfuzz/ && go build -o libpfuzz.a -tags=blst_enabled -buildmode=c-archive pfuzz.go


#####################################
############ teku #################

WORKDIR /

ARG TEKU_GIT_BRANCH="0.12.9"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y \
		openjdk-11-jdk clang openjdk-11-jre build-essential default-jdk

# set teku environment variables
# RUN export JAVA_HOME="$(dirname $(dirname $(readlink -f $(command -v java))))"
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 

ENV LD_LIBRARY_PATH=$JAVA_HOME/lib/server

# Clone the project
RUN git clone \
	--branch "$TEKU_GIT_BRANCH" \
	--recursive \
 	--depth 1 \
	https://github.com/PegaSysEng/teku.git

WORKDIR /teku

# Build teku
# RUN BFUZZ_TEKU_DIR="$(realpath -e .)" && export BFUZZ_TEKU_DIR
ENV BFUZZ_TEKU_DIR=/teku/

RUN ./gradlew installDist fuzz:build -x test --stacktrace

#####################################
########### Rust fuzzer #############

# Install Rust fuzzer
RUN cargo install honggfuzz
RUN cargo install cargo-fuzz
RUN cargo install afl

#####################################
############ eth2fuzz ###############

WORKDIR /beacon-fuzz/beaconfuzz_v2

# Copy all
COPY . .

# Build the CLI tool
RUN make build-docker

ENTRYPOINT ["/beacon-fuzz/beaconfuzz_v2/beaconfuzz_v2"]
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

###################################
############ teku #################

FROM ubuntu:18.04

ARG GIT_BRANCH="master"
ARG T_VERSION="0.12.5"
ARG PRESET="preset_mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		git \
		unzip \
		curl \
		make \
		build-essential \
		maven

# Install afl++
RUN apt-get install -y \
	build-essential \
	libtool-bin python3-dev \
	automake flex bison \
	libglib2.0-dev libpixman-1-dev \
	clang python3-setuptools \
	llvm

RUN git clone \
	--branch "$GIT_BRANCH" \
	--depth 1 \
	https://github.com/AFLplusplus/AFLplusplus

RUN cd AFLplusplus && make distrib
RUN cd AFLplusplus && make install


# Install JAVA
RUN apt-get update && \
	apt-get install -y \
		openjdk-11-jdk

WORKDIR /eth2fuzz

# TODO uncomment once a9abcb472cab80cda3652268aec2a03ee8bfc1d7 is part of a suitable Teku release
#RUN git clone \
#	--branch "$TEKU_VERSION" \
#	--depth 1 \
#	https://github.com/PegaSysEng/teku.git

RUN git clone \
	--branch "$T_VERSION" \
	--depth 1 \
	https://github.com/PegaSysEng/teku.git

# Build Teku
RUN cd teku && \
	./gradlew distTar installDist

# install JQF fuzzer
RUN git clone --depth 1 \
	https://github.com/rohanpadhye/jqf
RUN jqf/setup.sh


#####################################
############ eth2fuzz ###############

# COPY --from=build shared .
COPY --from=build /eth2fuzz/eth2fuzz .

# Set env for eth2fuzz target listing
ENV CURRENT_CLIENT="TEKU"

ENTRYPOINT ["/eth2fuzz/eth2fuzz"]

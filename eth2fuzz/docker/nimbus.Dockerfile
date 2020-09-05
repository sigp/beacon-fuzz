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

# Nimbus doesn't use git tags for versioning, so pin to specific commit
ARG NIMBUS_GIT_BRANCH="devel"
ARG NIMBUS_GIT_COMMIT="207397775b86f7244bf3e7226a54375d512c976a"
ARG NIMUTIL_GIT_BRANCH="master"
#ARG NIMUTIL_GIT_COMMIT="61e5e1ec817cc73fc43585acae4def287180e78e"
ARG NIMUTIL_GIT_COMMIT="1601894ec1fd1c7095d405eb0c846cac212fb18f"
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
	--recurse-submodules \
	https://github.com/status-im/nim-testutils && \
    cd nim-testutils && \
    git checkout "$NIMUTIL_GIT_COMMIT" \
    --recurse-submodules

# Clone the project
RUN git clone \
	--branch "$NIMBUS_GIT_BRANCH" \
	--recurse-submodules \
 	--single-branch \
	https://github.com/status-im/nim-beacon-chain && \
    cd nim-beacon-chain && \
    git checkout "$NIMBUS_GIT_COMMIT" \
	--recurse-submodules


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

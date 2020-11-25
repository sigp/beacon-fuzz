FROM ubuntu:18.04 AS build

ARG GIT_BRANCH="master"
ARG PRESET="preset_mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		software-properties-common \
		curl

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

WORKDIR /app

RUN git clone \
	--branch "$GIT_BRANCH" \
	--depth 1 \
	https://github.com/prysmaticlabs/prysm

RUN cd prysm && \
	# Build pcli
	bazel build //tools/pcli:pcli

#
# Exporting compiled binaries 
#
FROM scratch AS export

# Copy over the CLI from the build phase
COPY --from=build /app/prysm/bazel-bin/tools/pcli/pcli_/pcli .

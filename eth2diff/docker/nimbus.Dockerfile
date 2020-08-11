FROM ubuntu:18.04 AS build

ARG GIT_BRANCH="devel"
ARG PRESET="mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		cmake \
		build-essential \
		git \
		libpcre3-dev

# Clone the project
RUN git clone \
	--branch "$GIT_BRANCH" \
 	--depth 1 \
	https://github.com/status-im/nim-beacon-chain

WORKDIR nim-beacon-chain

# Build nimbus
RUN make ncli \
	libnfuzz.so libnfuzz.a

#
# Exporting compiled binaries 
#
FROM scratch AS export

COPY --from=build /nim-beacon-chain/build/libnfuzz* .
COPY --from=build /nim-beacon-chain/build/ncli .

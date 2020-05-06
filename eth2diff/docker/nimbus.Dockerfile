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

# First `make` invocation
# will update all Git submodules
RUN make
# TODO - only make tools we need

# Second `make` invocation
# will compiled everything
# RUN make NIMFLAGS="-d:chronicles_log_level=ERROR -d:release -d:const_preset=$PRESET" all

#
# Exporting compiled binaries 
#
FROM scratch AS export

COPY --from=build /nim-beacon-chain/build/* .
# TODO - only copy needed tools

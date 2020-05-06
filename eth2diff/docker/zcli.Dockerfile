FROM ubuntu:18.04 AS build

ARG GIT_BRANCH="master"
ARG PRESET="preset_mainnet"

# Update ubuntu
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		software-properties-common \
		git

# Install Golang
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update && \
	apt-get install -y \
	golang

WORKDIR /app

RUN git clone \
	--branch "$GIT_BRANCH" \
	--depth 1 \
	https://github.com/protolambda/zcli

RUN cd zcli && \
	# Build ZCLI, the ZRNT command line interface!
	go build -o zcli -tags $PRESET -v -i .

#
# Exporting compiled binaries 
#
FROM scratch AS export

# Copy over the CLI from the build phase
COPY --from=build /app/zcli/zcli .

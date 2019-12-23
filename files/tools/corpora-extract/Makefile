.PHONY: build clean test help default

BIN_NAME=corpora-extract

VERSION := $(shell grep "const Version " version/version.go | sed -E 's/.*"(.+)"$$/\1/')
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_DIRTY=$(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
BUILD_DATE=$(shell date '+%Y-%m-%d-%H:%M:%S')

default: build

help:
	@echo 'Management commands for corpora-extract:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	@echo '    make clean           Clean the directory tree.'
	@echo

build:
	#@echo "building ${BIN_NAME} ${VERSION}"
	#@echo "GOPATH=${GOPATH}"
	GO111MODULE=on go build -tags 'preset_mainnet' -ldflags "-X github.com/sigp/beacon-fuzz/tools/corpora-extract/version.GitCommit=${GIT_COMMIT}${GIT_DIRTY} -X github.com/sigp/beacon-fuzz/tools/corpora-extract/version.BuildDate=${BUILD_DATE}" -o bin/${BIN_NAME}

clean:
	@test ! -e bin/${BIN_NAME} || rm bin/${BIN_NAME}

test:
	go test ./...

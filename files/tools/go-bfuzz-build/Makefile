.PHONY: build clean test help default

BIN_NAME=go-bfuzz-build

default: build

help:
	@echo 'Management commands for corpora-extract:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	@echo '	   make install         Install binary to local goroot'
	@echo '    make clean           Clean the directory tree.'
	@echo

build:
	#@echo "building ${BIN_NAME} ${VERSION}"
	#@echo "GOPATH=${GOPATH}"
	GO111MODULE=on go build -o bin/${BIN_NAME}

install:
	GO111MODULE=on go install

clean:
	@test ! -e bin/${BIN_NAME} || rm bin/${BIN_NAME}

test:
	go test ./...

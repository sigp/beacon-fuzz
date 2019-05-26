#!/bin/bash

cd /eth2

export CC=clang-6.0
export CXX=clang++-6.0

# Set env variables for using Golang
export GOROOT=`realpath go`
export GOPATH=$GOROOT/packages
mkdir $GOPATH
export PATH=$GOROOT/bin:$PATH
export PATH=$GOROOT/packages/bin:$PATH

# Get custom go-fuzz
mkdir -p $GOPATH/src/github.com/dvyukov
cd $GOPATH/src/github.com/dvyukov
git clone https://github.com/guidovranken/go-fuzz.git
cd go-fuzz
git checkout libfuzzer-extensions

cd /eth2

go get golang.org/x/tools/go/packages
go build github.com/dvyukov/go-fuzz/go-fuzz-build
export GO_FUZZ_BUILD_PATH=`realpath go-fuzz-build`

# CPython
mkdir cpython-install
export CPYTHON_INSTALL_PATH=`realpath cpython-install`
cd cpython
./configure --prefix=$CPYTHON_INSTALL_PATH
make -j$(nproc)
make install

cd /eth2/lib
make

cd /eth2/fuzzers
# Recursively make all fuzzers
make

# Find fuzzers, copy them over
#find . -type f ! -name '*.*' -executable -exec cp {} /eth2/out \;

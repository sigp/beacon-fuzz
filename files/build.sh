#!/bin/bash

curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

cd /eth2

export CC=clang-6.0
export CXX=clang++-6.0

# CPython
mkdir cpython-install
export CPYTHON_INSTALL_PATH=`realpath cpython-install`
cd cpython
# TODO worth adding --enable-optimizations?
./configure --prefix=$CPYTHON_INSTALL_PATH
make -j$(nproc)
make install
# Upgrade pip 
"$CPYTHON_INSTALL_PATH/bin/python3" -m pip install --upgrade pip

cd /eth2
# Get eth2.0-specs
git clone --depth 1 --branch v0.8.3 https://github.com/ethereum/eth2.0-specs.git
export ETH2_SPECS_PATH=`realpath eth2.0-specs/`

# Build pyspec and dependencies
cd "$ETH2_SPECS_PATH"
make pyspec
export PY_SPEC_VENV_PATH="$ETH2_SPECS_PATH/venv"
rm -rf "$PY_SPEC_VENV_PATH"
"$CPYTHON_INSTALL_PATH/bin/python3" -m venv "$PY_SPEC_VENV_PATH"
"$PY_SPEC_VENV_PATH/bin/pip" install --upgrade pip
cd "$ETH2_SPECS_PATH/test_libs/pyspec"
"$PY_SPEC_VENV_PATH/bin/pip" install -r "./requirements.txt"
"$PY_SPEC_VENV_PATH/bin/pip" install -e .
cd "$ETH2_SPECS_PATH/test_libs/config_helpers"
"$PY_SPEC_VENV_PATH/bin/pip" install -r "./requirements.txt"
"$PY_SPEC_VENV_PATH/bin/pip" install -e .

# Now any script run with the python executable below will have access to pyspec
export PY_SPEC_BIN_PATH="$PY_SPEC_VENV_PATH/bin/python3"

# as any modifications to the pyspec occur at runtime (monkey patching), its
# ok to have a centralized pyspec codebase for all fuzzing targets

cd /eth2/lib
# NOTE this doesn't depend on any GOPATH
make
cd /eth2

# Set env variables for using Golang
export GOROOT=`realpath go`
export PATH="$GOROOT/bin:$PATH"
export GO111MODULE="off" # not supported by go-fuzz, keep it off unless explicitly enabled

# Get and configure zrnt
ZRNT_GOPATH="/eth2/zrnt_gopath/"
ZRNT_TMP="/eth2/zrnt_tmp/"
# TODO choose to error or remove if these paths already exist?
rm -rf "$ZRNT_GOPATH"
rm -rf "$ZRNT_TMP"
mkdir -p "$ZRNT_TMP"
cd $ZRNT_TMP
git clone --depth 1 --branch v0.8.3 https://github.com/protolambda/zrnt.git
cd zrnt
# TODO variables for relevant spec release and tags - a manifest file?

# hacky way to use module dependencies with go fuzz
# see https://github.com/dvyukov/go-fuzz/issues/195#issuecomment-523526736
# TODO avoid a single GOPATH passed everywhere
# TODO have a zrnt go dependency section
# turn GO111MODULE on in case it was set off or auto in go v1.12
GO111MODULE="on" go mod vendor
mkdir -p "$ZRNT_GOPATH/src/"
# TODO does this copy the file or only the directories? i.e. does */ do any different to *?
mv vendor/*/ "$ZRNT_GOPATH/src/"
rm -rf vendor
mkdir -p $ZRNT_GOPATH/src/github.com/protolambda
cd ..
mv zrnt "$ZRNT_GOPATH/src/github.com/protolambda/"

cd /eth2
rm -rf $ZRNT_TMP
# Now ZRNT_GOPATH contains (only) zrnt and all its dependencies.

export GOPATH="$GOROOT/packages"
mkdir $GOPATH
export PATH="$GOPATH/bin:$PATH"

# Get custom go-fuzz
mkdir -p $GOPATH/src/github.com/dvyukov
cd $GOPATH/src/github.com/dvyukov
git clone https://github.com/guidovranken/go-fuzz.git
cd go-fuzz
git checkout libfuzzer-extensions

cd /eth2

# TODO should this be in a ZRNT specific spot or common fuzzer?
# common $GOPATH for now
go get github.com/cespare/xxhash
# TODO what is packages used for?
go get golang.org/x/tools/go/packages
go build github.com/dvyukov/go-fuzz/go-fuzz-build
export GO_FUZZ_BUILD_PATH=`realpath go-fuzz-build`

mkdir -p $GOPATH/src/github.com/protolambda

# TODO why is eth2.0-specs in protolambda?
cd $GOPATH/src/github.com/protolambda
git clone --depth 1 --branch v0.8.3 https://github.com/ethereum/eth2.0-specs
cd /eth2

export GOPATH="$GOPATH:/eth2/lib/go:$ZRNT_GOPATH"

cd /eth2/fuzzers
# Recursively make all fuzzers
make all

# Find fuzzers, copy them over
#find . -type f ! -name '*.*' -executable -exec cp {} /eth2/out \;

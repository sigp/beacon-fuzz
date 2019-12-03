#!/bin/bash

curl https://sh.rustup.rs -sSf | sh -s -- -y
# shellcheck source=/dev/null
source "$HOME"/.cargo/env

cd /eth2 || exit

export CC=clang-8
export CXX=clang++-8
#export LDLIBS

# CPython
mkdir cpython-install
CPYTHON_INSTALL_PATH="$(realpath cpython-install)"
export CPYTHON_INSTALL_PATH
cd cpython || exit
# TODO worth adding --enable-optimizations?
./configure --prefix="$CPYTHON_INSTALL_PATH"
make "-j$(nproc)"
make install
# Upgrade pip
"$CPYTHON_INSTALL_PATH"/bin/python3 -m pip install --upgrade pip

cd /eth2 || exit
# Get eth2.0-specs
git clone --depth 1 --branch v0.9.1 https://github.com/ethereum/eth2.0-specs.git
# TODO quote here?
ETH2_SPECS_PATH=$(realpath eth2.0-specs/)
# TODO do we care about this?
export ETH2_SPECS_PATH

# Build pyspec and dependencies
cd "$ETH2_SPECS_PATH" || exit
make pyspec
export PY_SPEC_VENV_PATH="$ETH2_SPECS_PATH"/venv
# TODO still delete and start from scratch?
rm -rf "$PY_SPEC_VENV_PATH"
"$CPYTHON_INSTALL_PATH"/bin/python3 -m venv "$PY_SPEC_VENV_PATH"
"$PY_SPEC_VENV_PATH"/bin/pip install --upgrade pip
cd "$ETH2_SPECS_PATH"/test_libs/pyspec || exit
# don't need to use requirements.py as the setup.py contains pinned dependencies
# TODO use editable install "-e ." once editable venvs are supported
"$PY_SPEC_VENV_PATH"/bin/pip install .
cd "$ETH2_SPECS_PATH"/test_libs/config_helpers || exit
# TODO use editable install "-e ." once editable venvs are supported
"$PY_SPEC_VENV_PATH"/bin/pip install .

# Now any script run with the python executable below will have access to pyspec
export PY_SPEC_BIN_PATH="$PY_SPEC_VENV_PATH"/bin/python3

# as any modifications to the pyspec occur at runtime (monkey patching), its
# ok to have a centralized pyspec codebase for all fuzzing targets

# TODO specify Trinity tag/branch
git clone --branch master https://github.com/ethereum/trinity.git /eth2/trinity
cd /eth2/trinity || exit
git checkout fcea7124effca010db62bd41a24dd7975825ba90 || exit
export TRINITY_VENV_PATH="/eth2/trinity/venv"
# TODO still delete and start from scratch?
rm -rf "$TRINITY_VENV_PATH"
"$CPYTHON_INSTALL_PATH"/bin/python3 -m venv "$TRINITY_VENV_PATH"
"$TRINITY_VENV_PATH"/bin/pip install --upgrade pip
"$TRINITY_VENV_PATH"/bin/pip install .
# Now any script run with the python executable below will have access to trinity
export TRINITY_BIN_PATH="$TRINITY_VENV_PATH"/bin/python3

cd /eth2/lib || exit
# NOTE this doesn't depend on any GOPATH
# TODO || exit if make fails?
make "-j$(nproc)"
cd /eth2 || exit

# Set env variables for using Golang
GOROOT=$(realpath go)
export GOROOT
export PATH="$GOROOT/bin:$PATH"
export GO111MODULE="off" # not supported by go-fuzz, keep it off unless explicitly enabled

# Get and configure zrnt
ZRNT_GOPATH="/eth2/zrnt_gopath/"
ZRNT_TMP="/eth2/zrnt_tmp/"
# TODO choose to error or remove if these paths already exist?
rm -rf "$ZRNT_GOPATH"
rm -rf "$ZRNT_TMP"
mkdir -p "$ZRNT_TMP"
cd "$ZRNT_TMP" || exit
git clone --depth 1 --branch v0.9.1 https://github.com/protolambda/zrnt.git
cd zrnt || exit
# TODO variables for relevant spec release and tags - a manifest file?

# hacky way to use module dependencies with go fuzz
# see https://github.com/dvyukov/go-fuzz/issues/195#issuecomment-523526736
# TODO avoid a single GOPATH passed everywhere
# TODO have a zrnt go dependency section
# turn GO111MODULE on in case it was set off or auto in go v1.12
GO111MODULE="on" go mod vendor
mkdir -p "$ZRNT_GOPATH"/src/
# TODO does this copy the file or only the directories? i.e. does */ do any different to *?
mv vendor/*/ "$ZRNT_GOPATH"/src/
rm -rf vendor
mkdir -p "$ZRNT_GOPATH"/src/github.com/protolambda
cd .. || exit
mv zrnt "$ZRNT_GOPATH"/src/github.com/protolambda/

cd /eth2 || exit
rm -rf $ZRNT_TMP
# Now ZRNT_GOPATH contains (only) zrnt and all its dependencies.

export GOPATH="$GOROOT"/packages
mkdir "$GOPATH"
export PATH="$GOPATH/bin:$PATH"

# Get custom go-fuzz
mkdir -p "$GOPATH"/src/github.com/dvyukov
cd "$GOPATH"/src/github.com/dvyukov || exit
git clone https://github.com/guidovranken/go-fuzz.git
cd go-fuzz || exit
git checkout libfuzzer-extensions

cd /eth2 || exit

# TODO should this be in a ZRNT specific spot or common fuzzer?
# common $GOPATH for now
go get github.com/cespare/xxhash
# TODO what is packages used for?
go get golang.org/x/tools/go/packages
go build github.com/dvyukov/go-fuzz/go-fuzz-build
GO_FUZZ_BUILD_PATH=$(realpath go-fuzz-build)
export GO_FUZZ_BUILD_PATH

export GOPATH="$GOPATH:/eth2/lib/go:$ZRNT_GOPATH"

echo "Saving exported env to /eth2/exported_env.sh"
export -p >/eth2/exported_env.sh

cd /eth2/fuzzers || exit
# Recursively make all fuzzers
# TODO or exit?

make all "-j$(nproc)"

# Find fuzzers, copy them over
#find . -type f ! -name '*.*' -executable -exec cp {} /eth2/out \;

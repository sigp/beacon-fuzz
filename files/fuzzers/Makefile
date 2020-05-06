here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

# TODO remove when Trinity supports v0.10.1
BFUZZ_TRINITY_OFF:=1

CARGO_CONFIG_PATH := $(realpath ../.cargo/config)

GO_BFUZZ_BUILD ?= go-bfuzz-build

# TODO(gnattishness bls enable/disable option)

# NOTE this is both LD_FLAGS and LDLIBS for Python-related stuff
PYTHON_LDFLAGS := $(shell $(CPYTHON_INSTALL_PATH)/bin/python3-config --ldflags) -lpython3.8 -Xlinker -export-dynamic

# TODO use python3-config --cflags, -g?
CXXFLAGS+=-I"$(realpath ..)" -I"$(CPYTHON_INSTALL_PATH)/include/python3.8" -fsanitize=fuzzer-no-link -std=c++17
LDFLAGS+=-L"$(realpath ../lib)"
LDLIBS+= -leth2fuzz -lstdc++fs
export

TARGETS := attestation attester_slashing block block_header deposit proposer_slashing shuffle voluntary_exit

# TODO this has a problem e.g. `make block clean` will call `make -C /eth2/fuzzers/voluntary_exit clean -f ../fuzzer.mk` and then `make clean block`
# which will try to build all targets with `make block`
# Desired behavior is to call `make clean` for only the block target
.PHONY: all clean mostlyclean
all clean mostlyclean: $(TARGETS)

.PHONY: $(TARGETS)
$(TARGETS):
	@# $(here) used so this can be called from other directories
	$(MAKE) -C $(here)/$@ $(filter-out $@,$(MAKECMDGOALS)) -f ../fuzzer.mk

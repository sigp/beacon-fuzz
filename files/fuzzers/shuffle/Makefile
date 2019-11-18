shuffle_root := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

PY_SPEC_HARNESS_PATH := $(shuffle_root)/pyspec/harness.py

lighthouse_dir_contents := $(shell find $(shuffle_root)/lighthouse | sed 's/ /\\ /g')

zrnt_prefix := shuffle_
prysm_prefix := prysm_shuffle_

all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release
	cp lighthouse_out/release/deps/libswap_or_not_shuffle_fuzzer-*.a lighthouse.a

prysm.a : export GOPATH := $(COMMON_GOPATH):$(PRYSM_GOPATH)
prysm.a : prysm/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd prysm && "$(GO_FUZZ_BUILD_PATH)" -libfuzzer-prefix=$(prysm_prefix) -libfuzzer-ex -o ../prysm.a .

zrnt.a : export GOPATH := $(COMMON_GOPATH):$(ZRNT_GOPATH)
zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && "$(GO_FUZZ_BUILD_PATH)" -tags preset_mainnet -libfuzzer-prefix=$(zrnt_prefix) -libfuzzer-ex -o ../zrnt.a .

# TODO would optimally want this rebuilt if the env var values changed
# https://stackoverflow.com/questions/11647859/make-targets-depend-on-variables
fuzzer : fuzzer.cpp zrnt.a lighthouse.a prysm.a
	test $(shuffle_root)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" -DPRYSM_FUZZ_PREFIX=$(prysm_prefix) -DGO_FUZZ_PREFIX=$(zrnt_prefix) fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pyspec/eth2_specs lighthouse_out

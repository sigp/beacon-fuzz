SHUFFLE_ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))


PY_SPEC_HARNESS_PATH := $(SHUFFLE_ROOT)/pyspec/harness.py

lighthouse_dir_contents := $(shell find $(SHUFFLE_ROOT)/lighthouse | sed 's/ /\\ /g')

all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents)
	# TODO add coverage flags, llvm args to Rust build
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release
	cp lighthouse_out/release/deps/libswap_or_not_shuffle_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && "$(GO_FUZZ_BUILD_PATH)" -tags preset_mainnet -libfuzzer-prefix=shuffle_ -libfuzzer-ex -o ../zrnt.a .

# might not actually need to depend on the python harness here as interpreted?
# TODO would optimally want this rebuilt if the env var values changed
# https://stackoverflow.com/questions/11647859/make-targets-depend-on-variables
fuzzer : fuzzer.cpp zrnt.a pyspec/harness.py lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pyspec/eth2_specs lighthouse_out

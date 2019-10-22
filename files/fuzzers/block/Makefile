BLOCK_ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

lighthouse_dir_contents := $(shell find $(SHUFFLE_ROOT)/lighthouse | sed 's/ /\\ /g')

all: fuzzer

PY_SPEC_HARNESS_PATH := $(BLOCK_ROOT)/pyspec/harness.py

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=block_ -libfuzzer-ex -o ../zrnt.a .

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
	cp lighthouse_out/release/deps/libblock_fuzzer-*.a lighthouse.a


fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

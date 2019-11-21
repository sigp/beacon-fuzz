block_root := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

lighthouse_dir_contents := $(shell find $(block_root)/lighthouse | sed 's/ /\\ /g')

PY_SPEC_HARNESS_PATH := $(block_root)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(block_header_root)/trinity/harness.py

all: fuzzer

zrnt.a : zrnt/fuzz.go
	test -x $(GO_FUZZ_BUILD_PATH)
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
	test -x $(TRINITY_BIN_PATH)
	test -x $(PY_SPEC_BIN_PATH)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 \
	    -DPY_SPEC_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" \
	    -DPY_SPEC_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" \
	    -DTRINITY_HARNESS_PATH="\"$(TRINITY_HARNESS_PATH)\"" \
	    -DTRINITY_HARNESS_BIN="\"$(TRINITY_BIN_PATH)\"" \
	    fuzzer.cpp zrnt.a lighthouse.a \
	    $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

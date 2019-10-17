BLOCK_HEADER_ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

PY_SPEC_HARNESS_PATH := $(BLOCK_HEADER_ROOT)/pyspec/harness.py

all: fuzzer

# TODO N depend on lib or GO_FUZZ_BUILD_PATH?
zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=block_header_ -libfuzzer-ex -o ../zrnt.a .

# TODO N consistent presets?!

lighthouse.a : lighthouse/
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release 
	# TODO N pass llvm args 
	# -Cpasses=sancov -Cllvm-args="-sanitizer-coverage-trace-pc-guard -sanitizer-coverage-trace-compares=1 -sanitizer-coverage-trace-geps=1 -sanitizer-coverage-trace-divs=1"
	cp lighthouse_out/release/deps/libblock_header_fuzzer-*.a lighthouse.a

# TODO N depend on lib/*.h etc?
fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

PY_SPEC_HARNESS_PATH := $(here)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(here)/trinity/harness.py

lighthouse_dir_contents := $(shell find $(here)/lighthouse | sed 's/ /\\ /g')

.PHONY: all
all: fuzzer

# TODO N depend on lib or GO_FUZZ_BUILD_PATH?
zrnt.a : zrnt/fuzz.go
	test -x $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags 'preset_mainnet bls_off' -libfuzzer-prefix=block_header_ -libfuzzer-ex -o ../zrnt.a .

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--features fake_crypto \
		--release
	cp lighthouse_out/release/deps/libblock_header_fuzzer-*.a lighthouse.a

# TODO N depend on lib/*.h etc?
fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	test -d $(TRINITY_VENV_PATH)
	test -d $(PY_SPEC_VENV_PATH)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 \
	    -DPY_SPEC_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" \
	    -DPY_SPEC_VENV_PATH="\"$(PY_SPEC_VENV_PATH)\"" \
	    -DTRINITY_HARNESS_PATH="\"$(TRINITY_HARNESS_PATH)\"" \
	    -DTRINITY_VENV_PATH="\"$(TRINITY_VENV_PATH)\"" \
	    fuzzer.cpp zrnt.a lighthouse.a \
	    $(LDFLAGS) $(LDLIBS) $(PYTHON_LDFLAGS) -o fuzzer

.PHONY: clean
clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

PY_SPEC_HARNESS_PATH := $(here)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(here)/trinity/harness.py

lighthouse_dir_contents := $(shell find $(here)/lighthouse | sed 's/ /\\ /g')

.PHONY: all
all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cp lighthouse_out/release/deps/libattestation_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=attestation_ -libfuzzer-ex -o ../zrnt.a .

fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	test -d $(TRINITY_VENV_PATH)
	test -d $(PY_SPEC_VENV_PATH)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 \
	    -DPY_SPEC_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" \
	    -DPY_SPEC_VENV_PATH="\"$(PY_SPEC_VENV_PATH)\"" \
	    -DTRINITY_HARNESS_PATH="\"$(TRINITY_HARNESS_PATH)\"" \
	    -DTRINITY_VENV_PATH="\"$(TRINITY_VENV_PATH)\"" \
	    fuzzer.cpp zrnt.a lighthouse.a \
	    $(LDFLAGS) $(LDLIBS) $(PYTHON_LD_FLAGS) -o fuzzer

.PHONY: clean
clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

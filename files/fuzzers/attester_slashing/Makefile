here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

lighthouse_dir_contents := $(shell find $(here)/lighthouse | sed 's/ /\\ /g')

PY_SPEC_HARNESS_PATH := $(here)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(here)/trinity/harness.py

# TODO(gnattishness) uncomment when nimbus harness is implemented for this target
#ifndef NIM_CPPFLAGS
#$(error NIM_CPPFLAGS is not set)
#endif
#ifndef NIM_LDFLAGS
#$(error NIM_LDFLAGS is not set)
#endif
#ifndef NIM_LDLIBS
#$(error NIM_LDLIBS is not set)
#endif

.PHONY: all clean
all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--features fake_crypto \
		--release
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cp lighthouse_out/release/deps/libattester_slashing_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags 'preset_mainnet bls_off' -libfuzzer-prefix=attester_slashing_ -libfuzzer-ex -o ../zrnt.a .

fuzzer.o : CPPFLAGS += $(NIM_CPPFLAGS)
fuzzer.o : fuzzer.cpp
	test -d $(TRINITY_VENV_PATH)
	test -d $(PY_SPEC_VENV_PATH)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS)\
	    -DPY_SPEC_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" \
	    -DPY_SPEC_VENV_PATH="\"$(PY_SPEC_VENV_PATH)\"" \
	    -DTRINITY_HARNESS_PATH="\"$(TRINITY_HARNESS_PATH)\"" \
	    -DTRINITY_VENV_PATH="\"$(TRINITY_VENV_PATH)\"" \
		-c fuzzer.cpp -o fuzzer.o

#fuzzer : LDFLAGS += $(NIM_LDFLAGS)
#fuzzer : LDLIBS += $(NIM_LDLIBS)
fuzzer : fuzzer.o zrnt.a lighthouse.a
	$(CXX) -fsanitize=fuzzer \
	    fuzzer.o zrnt.a lighthouse.a \
	    $(LDFLAGS) $(LDLIBS) $(PYTHON_LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer *.a *.o lighthouse_out

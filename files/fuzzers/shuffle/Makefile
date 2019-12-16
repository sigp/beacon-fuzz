here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

PY_SPEC_HARNESS_PATH := $(here)/pyspec/harness.py
TRINITY_HARNESS_PATH := $(here)/trinity/harness.py

lighthouse_dir_contents := $(shell find $(here)/lighthouse | sed 's/ /\\ /g')

ifndef NIM_CPPFLAGS
$(error NIM_CPPFLAGS is not set)
endif
ifndef NIM_LDFLAGS
$(error NIM_LDFLAGS is not set)
endif
ifndef NIM_LDLIBS
$(error NIM_LDLIBS is not set)
endif

.PHONY: all clean
all: fuzzer

# NOTE bls disable not necessary here
# worth putting a dummy in for a consistent makefile?

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

zrnt.a : zrnt/fuzz.go
	test -x $(GO_FUZZ_BUILD_PATH)
	cd zrnt && "$(GO_FUZZ_BUILD_PATH)" -tags preset_mainnet -libfuzzer-prefix=shuffle_ -libfuzzer-ex -o ../zrnt.a .

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

# TODO would optimally want this rebuilt if the env var values changed
# https://stackoverflow.com/questions/11647859/make-targets-depend-on-variables
# TODO move LDFLAGS before and use LDLIBS for all -llibname flags
# TODO how to split up the PYTHON_LDFLAGS?
#
# TODO N depend on lib/*.h etc?
# NOTE: its not nice to have the python `-L` flags after LDLIBS,
# but -leth2fuzz depends on -lpython, so we have to link -lpython after

fuzzer : LDFLAGS += $(NIM_LDFLAGS)
fuzzer : LDLIBS += $(NIM_LDLIBS)
fuzzer : fuzzer.o zrnt.a lighthouse.a
	$(CXX) -fsanitize=fuzzer \
	    fuzzer.o zrnt.a lighthouse.a \
	    $(LDFLAGS) $(LDLIBS) $(PYTHON_LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer *.a *.o lighthouse_out

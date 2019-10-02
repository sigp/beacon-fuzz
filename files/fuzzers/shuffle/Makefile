SHUFFLE_ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

all: fuzzer

# NOTE assumes the pwd is the 
PYTHON_HARNESS_DIR := $(SHUFFLE_ROOT)/pyspec/eth2_specs/test_libs/pyspec/
PYTHON_HARNESS_PATH := $(PYTHON_HARNESS_DIR)/spec.py

pyspec/eth2_specs/test_libs/pyspec/spec.py : pyspec/harness.py
	test "$(ETH2_SPECS_PATH)"
	test "$(PYTHON_HARNESS_DIR)"
	rm -rf pyspec/eth2_specs
	mkdir -p pyspec/eth2_specs
	cp -R "$(ETH2_SPECS_PATH)/"* pyspec/eth2_specs
	cd pyspec/eth2_specs && make pyspec
	cp pyspec/eth2_specs/test_libs/pyspec/eth2spec/phase0/spec.py pyspec/eth2_specs/test_libs/pyspec
	cat pyspec/harness.py >> pyspec/eth2_specs/test_libs/pyspec/spec.py
	# install dependencies
	"$(CPYTHON_INSTALL_PATH)/bin/python3" -m venv "$(PYTHON_HARNESS_DIR)/venv"
	"$(PYTHON_HARNESS_DIR)/venv/bin/pip" install --upgrade pip
	"$(PYTHON_HARNESS_DIR)/venv/bin/pip" install -r "$(PYTHON_HARNESS_DIR)/requirements.txt"

lighthouse.a : lighthouse/
	# TODO add coverage flags to Rust build
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

fuzzer : fuzzer.cpp zrnt.a pyspec/eth2_specs/test_libs/pyspec/spec.py lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PYTHON_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PYTHON_HARNESS_DIR)/venv/bin/python\"" fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pyspec/eth2_specs lighthouse_out

BLOCK_ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

all: fuzzer

PY_SPEC_HARNESS_PATH := $(BLOCK_ROOT)/pyspec/harness.py

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_minimal -libfuzzer-prefix=block_ -libfuzzer-ex -o ../zrnt.a .


fuzzer : fuzzer.cpp zrnt.a pyspec/harness.py
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH="\"$(PY_SPEC_HARNESS_PATH)\"" -DPYTHON_HARNESS_BIN="\"$(PY_SPEC_BIN_PATH)\"" fuzzer.cpp zrnt.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pythonlib/

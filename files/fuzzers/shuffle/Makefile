all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath python/eth2_specs/test_libs/pyspec/spec.py)\""

python/eth2_specs/test_libs/pyspec/spec.py : python/harness.py
	test $(ETH2_SPECS_PATH)
	rm -rf python/eth2_specs
	mkdir -p python/eth2_specs
	cp -R $(ETH2_SPECS_PATH)/* python/eth2_specs
	cd python/eth2_specs && make phase0
	cp python/eth2_specs/test_libs/pyspec/eth2spec/phase0/spec.py python/eth2_specs/test_libs/pyspec
	cat python/harness.py >>python/eth2_specs/test_libs/pyspec/spec.py

go.a : go/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd go && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=shuffle_ -libfuzzer-ex -o ../go.a .

fuzzer : fuzzer.cpp go.a python/eth2_specs/test_libs/pyspec/spec.py
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) fuzzer.cpp go.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer go.a python/eth2_specs

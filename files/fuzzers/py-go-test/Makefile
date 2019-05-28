all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath python/fuzzer.py)\""

go.a : go/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd go && $(GO_FUZZ_BUILD_PATH) -libfuzzer-prefix=py_go_test_ -libfuzzer-ex -o ../go.a .

fuzzer : fuzzer.cpp go.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) fuzzer.cpp go.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer go.a

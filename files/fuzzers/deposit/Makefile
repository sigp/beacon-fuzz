all: fuzzer

go.a : go/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd go && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=deposit_ -libfuzzer-ex -o ../go.a .

fuzzer : fuzzer.cpp go.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp go.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer go.a

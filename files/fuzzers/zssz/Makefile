all: fuzzer

zssz.a : zssz/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zssz && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=zssz_ -libfuzzer-ex -o ../zssz.a .

fuzzer : fuzzer.cpp zssz.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp zssz.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer zssz.a

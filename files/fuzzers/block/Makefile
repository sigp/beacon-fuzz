all: fuzzer

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=block_ -libfuzzer-ex -o ../zrnt.a .

fuzzer : fuzzer.cpp zrnt.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp zrnt.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a

lighthouse_dir_contents := $(shell find $(SHUFFLE_ROOT)/lighthouse | sed 's/ /\\ /g')

all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release
	# TODO N pass llvm args
	# -Cpasses=sancov -Cllvm-args="-sanitizer-coverage-trace-pc-guard -sanitizer-coverage-trace-compares=1 -sanitizer-coverage-trace-geps=1 -sanitizer-coverage-trace-divs=1"
	cp lighthouse_out/release/deps/libattestation_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=attestation_ -libfuzzer-ex -o ../zrnt.a .

fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

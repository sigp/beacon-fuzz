all: fuzzer

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=block_header_ -libfuzzer-ex -o ../zrnt.a .

lighthouse.a : lighthouse/
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo rustc \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release -- \
		-Cpasses=sancov -Cllvm-args="-sanitizer-coverage-trace-pc-guard -sanitizer-coverage-trace-compares=1 -sanitizer-coverage-trace-geps=1 -sanitizer-coverage-trace-divs=1" \
		--crate-type=staticlib \
		--target x86_64-unknown-linux-gnu
	cp lighthouse_out/release/deps/libblock_header_fuzzer-*.a lighthouse.a

fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a

all: fuzzer

go.a : go/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd go && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=block_header_ -libfuzzer-ex -o ../go.a .

rust.a : rust/
	rm -rf rust.a
	rm -rf rust_out/
	mkdir rust_out/
	cargo rustc \
		--target-dir=rust_out \
		--manifest-path=rust/Cargo.toml \
		--release -- \
		-Cpasses=sancov -Cllvm-args="-sanitizer-coverage-trace-pc-guard -sanitizer-coverage-trace-compares=1 -sanitizer-coverage-trace-geps=1 -sanitizer-coverage-trace-divs=1" \
		--crate-type=staticlib \
		--target x86_64-unknown-linux-gnu
	cp rust_out/release/deps/libblock_header_fuzzer-*.a rust.a

fuzzer : fuzzer.cpp go.a rust.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp go.a rust.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer go.a

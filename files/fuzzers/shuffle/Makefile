all: fuzzer

PYTHON_HARNESS_PATH="\"$(realpath pyspec/eth2_specs/test_libs/pyspec/spec.py)\""

pyspec/eth2_specs/test_libs/pyspec/spec.py : pyspec/harness.py
	test $(ETH2_SPECS_PATH)
	rm -rf pyspec/eth2_specs
	mkdir -p pyspec/eth2_specs
	cp -R $(ETH2_SPECS_PATH)/* pyspec/eth2_specs
	cd pyspec/eth2_specs && make phase0
	cp pyspec/eth2_specs/test_libs/pyspec/eth2spec/phase0/spec.py pyspec/eth2_specs/test_libs/pyspec
	cat pyspec/harness.py >>pyspec/eth2_specs/test_libs/pyspec/spec.py

lighthouse.a : lighthouse/
	# TODO add coverage flags to Rust build
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo rustc \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release -- \
		--crate-type=staticlib \
		--target x86_64-unknown-linux-gnu
	cp lighthouse_out/release/deps/libswap_or_not_shuffle_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=shuffle_ -libfuzzer-ex -o ../zrnt.a .

fuzzer : fuzzer.cpp zrnt.a pyspec/eth2_specs/test_libs/pyspec/spec.py lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 -DPYTHON_HARNESS_PATH=$(PYTHON_HARNESS_PATH) fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) $(PYTHON_LD_FLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a pyspec/eth2_specs lighthouse_out

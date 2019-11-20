attestation_root := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

lighthouse_dir_contents := $(shell find $(attestation_root)/lighthouse | sed 's/ /\\ /g')

zrnt_prefix := shuffle_
prysm_prefix := prysm_shuffle_

all: fuzzer

lighthouse.a : lighthouse $(lighthouse_dir_contents) $(CARGO_CONFIG_PATH)
	rm -rf lighthouse.a
	rm -rf lighthouse_out/
	mkdir lighthouse_out/
	cargo build \
		--target-dir=lighthouse_out \
		--manifest-path=lighthouse/Cargo.toml \
		--release
	# NOTE: we can't pass coverage flags via RUSTFLAGS, so rely on a custom .cargo/config
	# until https://github.com/rust-lang/cargo/issues/6139 is resolved
	cp lighthouse_out/release/deps/libattestation_fuzzer-*.a lighthouse.a

zrnt.a : zrnt/fuzz.go
	test $(GO_FUZZ_BUILD_PATH)
	cd zrnt && $(GO_FUZZ_BUILD_PATH) -tags preset_mainnet -libfuzzer-prefix=attestation_ -libfuzzer-ex -o ../zrnt.a .

fuzzer : fuzzer.cpp zrnt.a lighthouse.a
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -std=c++17 fuzzer.cpp zrnt.a lighthouse.a $(LDFLAGS) -o fuzzer

clean:
	rm -rf fuzzer zrnt.a lighthouse.a lighthouse_out

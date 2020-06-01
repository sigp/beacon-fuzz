.PHONY: default update check-fmt help build docker corpora fmt clippy clean clean-all test test-debug test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer test-all

#
# User utils
#

default: build

help:
	@echo 'Management commands for eth2fuzz'
	@echo
	@echo 'Usage:'
	@echo '    make build 										Compile the project.'
	@echo '    make docker										TODO.'
	@echo '    make corpora		 								TODO.'
	@echo
	@echo '    make fmt 										Run Rust fmt.'
	@echo '    make clean 										Clean only eth2fuzz binary.'
	@echo '    make clean-all 									Clean all (eth2fuzz && compiled fuzz target harnesses).'
	@echo
	@echo '    make test		 								Simple test to check if eth2fuzz is working.'
	@echo '    make test-debug		 							Test running a simple wasm to a debugging tool.'
	@echo '    make test-{libfuzzer, hfuzz, afl}				Test one fuzzing hardness over choosen fuzzer.'
	@echo '    make test-all		 							Test one fuzzing hardness over all fuzzers.'
	@echo '    make test-continuously-{libfuzzer, hfuzz, afl}	Test all fuzzing hardness over choosen fuzzer.'
	@echo


# Build the project locally
build:
	cargo +nightly build --release --out-dir=. -Z unstable-options

# Build the docker
# NOTE: `make docker CACHE=--no-cache` to force docker update/build everything again
docker:
	echo "TODO docker"

# Create an initial corpora of wasm modules
corpora:
	echo "TODO ../script/corpora"

#
# Developer utils
#

# Run Rust fmt to make code cleaner
fmt:
	cargo fmt --all

# Run Rust clippy to make code cleaner
clippy:
	cargo clippy --all

# Clean only eth2fuzz target
clean:
	rm -rf target/

# Clean all (eth2fuzz && compiled fuzz target harnesses).
clean-all: clean
	rm -rf workspace/targets
	rm -rf workspace/debug
	rm -rf workspace/afl
	rm -rf workspace/hfuzz
	rm -rf workspace/libfuzzer
	rm -rf workspace/jsfuzz
	rm -rf workspace/nimafl
	rm -rf workspace/nimlibfuzzer

#
# Testing utils
#

# Simple test to check if eth2fuzz is working.
test: build
	./eth2fuzz list

# Test running a simple wasm to a debugging tool.
test-debug: build
	./eth2fuzz debug lighthouse_attestation
	./workspace/debug/target/debug/debug_lighthouse_attestation \
		workspace/corpora/beaconstate/004a360e8f5b1d4a32c158c2c688fc4e.ssz \
		workspace/corpora/attestation/05db7ea93a4ee2467a1a04f3a0fa8f38.ssz

# Run one fuzzing hardness over honggfuzz during 2s
test-hfuzz: build
	./eth2fuzz target lighthouse_attestation -t 2

# Run one fuzzing hardness over afl during 2s
test-afl: build
	./eth2fuzz target lighthouse_attestation --fuzzer afl -t 2

# Run one fuzzing hardness over libfuzzer during 2s
test-libfuzzer: build
	./eth2fuzz target lighthouse_attestation --fuzzer libfuzzer -t 2

# Run one fuzzing hardness over nim-libfuzzer during 2s
test-nim-libfuzzer: build
	./eth2fuzz target nimbus_enr --fuzzer NimLibfuzzer -t 2

# Run one fuzzing hardness over all fuzzer
test-all: test-hfuzz test-afl test-libfuzzer test-nim-libfuzzer

# Run all fuzzing hardness over honggfuzz
test-continuously-hfuzz: build
	./eth2fuzz continuously -t 2 --fuzzer honggfuzz

# Run all fuzzing hardness over libfuzzer
test-continuously-libfuzzer: build
	./eth2fuzz continuously -t 2 --fuzzer libfuzzer

# Run all fuzzing hardness over afl
test-continuously-afl: build
	./eth2fuzz continuously -t 2 --fuzzer afl

#
# CI utils
#

# Check code style quickly by running `rustfmt` over all code
check-fmt:
	cargo fmt --all -- --check

# Check code quality by running `clippy` over all code
check-clippy:
	cargo clippy --all -- --check
